//go:build windows

package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"directlan/internal/directpair"
	"directlan/internal/identity"
	"directlan/internal/localipc"
	"directlan/internal/platform"
	"directlan/internal/tunnel"
	"golang.org/x/sys/windows"
)

type profile struct {
	Code        string                    `json:"code"`
	Name        string                    `json:"name"`
	LocalIP     netip.Addr                `json:"local_ip"`
	Pending     bool                      `json:"pending"`
	Paused      bool                      `json:"paused"`
	Port        uint16                    `json:"port"`
	Router      bool                      `json:"router"`
	Firewall    bool                      `json:"firewall"`
	DisableSTUN bool                      `json:"disable_stun"`
	Nonce       [12]byte                  `json:"nonce"`
	Learned     map[string]netip.AddrPort `json:"learned,omitempty"`
}

type memberStatus struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	State         string    `json:"state"`
	RTT           float64   `json:"rtt_ms"`
	LastProbe     time.Time `json:"last_probe,omitzero"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	Checking      bool      `json:"checking"`
	misses        int
}

type node struct {
	mu         sync.Mutex
	keys       identity.State
	path       string
	p          profile
	roster     Code
	wg         *tunnel.Tunnel
	interfaces tunnel.DirectInterfaces
	egress     string
	endpoints  []netip.AddrPort
	scanned    bool
	discovery  string
	detail     string
	members    map[string]memberStatus
	wake       chan struct{}
}

func Run(ctx context.Context, identityPath, uiSID string) error {
	keys, err := identity.LoadOrCreate(identityPath)
	if err != nil {
		return err
	}
	n := &node{keys: keys, path: identityPath + ".mesh.json", wake: make(chan struct{}, 1)}
	var restore sync.Once
	loop, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); n.monitor(loop) }()
	err = directpair.RunWithHandler(ctx, identityPath, uiSID, func(ctx context.Context, req localipc.Request) (any, *localipc.Error) {
		restore.Do(func() {
			n.mu.Lock()
			defer n.mu.Unlock()
			if err := n.restore(); err != nil {
				n.detail = "Не удалось открыть сеть. " + err.Error()
			}
		})
		return n.handle(ctx, req)
	})
	cancel()
	n.mu.Lock()
	if n.wg != nil {
		_ = n.wg.Stop()
	}
	n.mu.Unlock()
	<-done
	return err
}

func memberID(m Member) string { return hex.EncodeToString(m.Identity) }
func (n *node) owner() bool    { return bytes.Equal(n.roster.Owner, n.keys.IdentityPublic()) }

func (n *node) restore() error {
	data, err := os.ReadFile(n.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var p profile
	if len(data) > 128<<10 || json.Unmarshal(data, &p) != nil {
		return errors.New("сохранённая сеть повреждена")
	}
	if p.Code == "" {
		return nil
	}
	code, err := Decode(p.Code, time.Time{})
	if err != nil || code.Kind != "network" {
		return errors.New("подпись сохранённого состава сети не совпадает")
	}
	if err := n.replace(p, code); err != nil {
		n.p, n.roster = p, code
		return err
	}
	return nil
}

func (n *node) save(p profile) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return identity.WritePrivateFile(n.path, data)
}

func localMember(code Code, public []byte) (Member, bool) {
	for _, m := range code.Members {
		if bytes.Equal(m.Identity, public) {
			return m, true
		}
	}
	return Member{}, false
}

func freeAddress(code Code) (netip.Addr, error) {
	used := make(map[netip.Addr]bool)
	for _, m := range code.Members {
		used[m.IP] = true
	}
	ip := code.Network.Addr().Next()
	for range MaxMembers {
		if !used[ip] {
			return ip, nil
		}
		ip = ip.Next()
	}
	return netip.Addr{}, errors.New("в сети уже 10 компьютеров")
}

func (n *node) open(p profile, code Code) (*tunnel.Tunnel, uint16, tunnel.DirectInterfaces, string, error) {
	interfaces, egress := directpair.PhysicalInterfaces()
	if p.Paused {
		return nil, p.Port, interfaces, egress, nil
	}
	self, admitted := localMember(code, n.keys.IdentityPublic())
	if admitted {
		public, err := n.keys.WireGuardPublic()
		if err != nil || !bytes.Equal(self.WireGuard, public) {
			return nil, 0, interfaces, egress, errors.New("ключ этого ПК не совпадает с допуском в сеть")
		}
		p.LocalIP = self.IP
	} else if !p.Pending {
		return nil, p.Port, interfaces, egress, nil
	}
	if !p.LocalIP.Is4() || !code.Network.Contains(p.LocalIP) || p.LocalIP == code.Network.Addr() {
		return nil, 0, interfaces, egress, errors.New("неверный виртуальный адрес этого ПК")
	}
	_, subnet, _ := net.ParseCIDR(code.Network.String())
	start := func(port uint16) (*tunnel.Tunnel, error) {
		domain := code.Session + "/" + hex.EncodeToString(code.Owner)
		wg, err := tunnel.NewSecureDirect(n.keys.WireGuardPrivate, p.LocalIP.AsSlice(), subnet, port, interfaces, domain, code.Masked)
		if err != nil {
			return nil, err
		}
		if err = wg.Start(); err != nil {
			return nil, err
		}
		if admitted {
			for _, m := range code.Members {
				if bytes.Equal(m.Identity, self.Identity) {
					continue
				}
				ep := p.Learned[memberID(m)]
				if !directpair.PublicEndpoint(ep) && len(m.Endpoints) != 0 {
					ep = m.Endpoints[0]
				}
				if !directpair.PublicEndpoint(ep) {
					ep = netip.AddrPort{}
				}
				if err = wg.AddSecureDirectPeer(memberID(m), m.WireGuard, m.IP.AsSlice(), ep); err != nil {
					_ = wg.Stop()
					return nil, err
				}
			}
		}
		return wg, nil
	}
	wg, err := start(p.Port)
	if p.Port != 0 && errors.Is(err, windows.WSAEADDRINUSE) {
		wg, err = start(0)
	}
	if err != nil {
		return nil, 0, interfaces, egress, err
	}
	port, err := wg.DirectPort()
	if err != nil {
		_ = wg.Stop()
		return nil, 0, interfaces, egress, err
	}
	return wg, port, interfaces, egress, nil
}

// Reconfigure as a transaction. A failed start or save restores the previous
// signed roster and recreates its routes before returning an error.
func (n *node) replace(p profile, code Code) error {
	oldP, oldCode, oldWG := n.p, n.roster, n.wg
	if oldWG != nil {
		if err := oldWG.Stop(); err != nil {
			n.wg, n.members = nil, nil
			n.detail = "Туннель остановлен. Не удалось завершить очистку маршрутов."
			return err
		}
	}
	wg, port, interfaces, egress, err := n.open(p, code)
	if err == nil {
		p.Port = port
		if self, ok := localMember(code, n.keys.IdentityPublic()); ok {
			p.LocalIP, p.Pending = self.IP, false
		}
		err = n.save(p)
	}
	if err != nil {
		if wg != nil {
			_ = wg.Stop()
		}
		n.wg = nil
		n.members = nil
		if oldWG != nil {
			var rollback error
			var rollbackPort uint16
			n.wg, rollbackPort, n.interfaces, n.egress, rollback = n.open(oldP, oldCode)
			if rollback == nil {
				oldP.Port = rollbackPort
				rollback = n.save(oldP)
			}
			if rollback != nil {
				if n.wg != nil {
					_ = n.wg.Stop()
					n.wg = nil
				}
				n.detail = "Не удалось восстановить прежний туннель."
				return errors.Join(err, rollback)
			}
			n.p, n.endpoints, n.scanned = oldP, nil, false
			n.requestCheck()
		}
		return err
	}
	n.p, n.roster, n.wg, n.interfaces, n.egress = p, code, wg, interfaces, egress
	n.members = make(map[string]memberStatus)
	n.endpoints, n.scanned, n.discovery, n.detail = nil, false, "Ищем внешний адрес…", ""
	if wg == nil {
		n.discovery = ""
	}
	n.requestCheck()
	return nil
}

func (n *node) requestCheck() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func (n *node) sign(code Code) (Code, string, error) {
	code.Signer = n.keys.IdentityPublic()
	code.Expires = time.Now().Add(30 * time.Minute)
	text, err := Encode(code, ed25519.PrivateKey(n.keys.IdentityPrivate))
	return code, text, err
}

func (n *node) create(name string, masked bool, p profile) error {
	var session [16]byte
	if _, err := rand.Read(session[:]); err != nil {
		return err
	}
	var code Code
	code.Kind, code.Session, code.Owner, code.Revision, code.Masked = "network", hex.EncodeToString(session[:]), n.keys.IdentityPublic(), 1, masked
	for attempts := 0; attempts < 48; attempts++ {
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		raw[0] = 10
		code.Network = netip.PrefixFrom(netip.AddrFrom4(raw), 24).Masked()
		_, subnet, _ := net.ParseCIDR(code.Network.String())
		conflict, _, err := platform.RouteConflict(subnet, 0)
		if err != nil {
			return err
		}
		if conflict {
			continue
		}
		key, err := n.keys.WireGuardPublic()
		if err != nil {
			return err
		}
		code.Members = []Member{{Identity: code.Owner, WireGuard: key, Name: name, IP: code.Network.Addr().Next()}}
		code, p.Code, err = n.sign(code)
		if err != nil {
			return err
		}
		p.Name, p.LocalIP = name, code.Members[0].IP
		return n.replace(p, code)
	}
	return errors.New("не найдена свободная виртуальная подсеть")
}

func (n *node) accept(text string, code Code) error {
	if code.Session != n.roster.Session || code.Network != n.roster.Network || !bytes.Equal(code.Owner, n.roster.Owner) || code.Masked != n.roster.Masked {
		return errors.New("код относится к другой сети или режиму защиты")
	}
	p := n.p
	p.Learned = cloneEndpoints(p.Learned)
	if n.owner() {
		if code.Kind != "request" || code.Member == nil {
			return errors.New("вставьте запрос участника")
		}
		next := n.roster
		next.Members = append([]Member(nil), next.Members...)
		m := *code.Member
		found := false
		for i, known := range next.Members {
			if !bytes.Equal(known.Identity, m.Identity) {
				continue
			}
			if !bytes.Equal(known.WireGuard, m.WireGuard) {
				return errors.New("ключ участника изменился. Сначала удалите его из сети")
			}
			m.IP, found = known.IP, true
			if len(m.Endpoints) == 0 {
				m.Endpoints = known.Endpoints
			}
			next.Members[i] = m
			break
		}
		if !found {
			if len(next.Members) >= MaxMembers {
				return errors.New("в сети уже 10 компьютеров")
			}
			var err error
			m.IP, err = freeAddress(next)
			if err != nil {
				return err
			}
			next.Members = append(next.Members, m)
		}
		delete(p.Learned, memberID(m))
		next.Revision++
		var err error
		next, p.Code, err = n.sign(next)
		if err != nil {
			return err
		}
		return n.replace(p, next)
	}
	if code.Kind != "network" {
		return errors.New("здесь нужен обновлённый код сети от владельца")
	}
	if code.Revision < n.roster.Revision {
		return errors.New("код сети устарел. Запросите свежий код у владельца")
	}
	if code.Revision == n.roster.Revision {
		old, _ := json.Marshal(n.roster.Members)
		current, _ := json.Marshal(code.Members)
		if !bytes.Equal(old, current) {
			return errors.New("состав сети изменён без новой версии")
		}
		return nil
	}
	if _, ok := localMember(code, n.keys.IdentityPublic()); !ok && n.p.Pending {
		return errors.New("владелец ещё не принял ваш запрос")
	}
	p.Pending, p.Code = false, strings.TrimSpace(text)
	// Fresh owner-approved endpoints supersede older learned addresses.
	p.Learned = nil
	return n.replace(p, code)
}

func cloneEndpoints(source map[string]netip.AddrPort) map[string]netip.AddrPort {
	result := make(map[string]netip.AddrPort)
	for k, v := range source {
		result[k] = v
	}
	return result
}

func (n *node) handle(_ context.Context, req localipc.Request) (any, *localipc.Error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	fail := func(err error) (any, *localipc.Error) {
		return nil, &localipc.Error{Code: "MESH", Message: err.Error()}
	}
	var args struct {
		Code        string `json:"code"`
		ID          string `json:"id"`
		Name        string `json:"name"`
		Masked      bool   `json:"masked"`
		Router      bool   `json:"router"`
		Firewall    bool   `json:"firewall"`
		DisableSTUN bool   `json:"disable_stun"`
	}
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &args) != nil {
		return fail(errors.New("неверные параметры"))
	}
	switch req.Method {
	case "mesh.status":
		return n.status(), nil
	case "mesh.disconnect", "mesh.resume", "mesh.restart":
		if n.p.Code == "" {
			return fail(errors.New("сначала создайте сеть или присоединитесь к ней"))
		}
		if req.Method == "mesh.resume" && n.wg != nil && !n.p.Paused {
			return n.status(), nil
		}
		p := n.p
		p.Paused = req.Method == "mesh.disconnect"
		if p.Paused && n.wg == nil && n.p.Paused {
			return n.status(), nil
		}
		if err := n.replace(p, n.roster); err != nil {
			return fail(err)
		}
	case "mesh.create", "mesh.join":
		if n.p.Code != "" {
			return fail(errors.New("сначала выйдите из текущей сети"))
		}
		name := strings.TrimSpace(args.Name)
		if name == "" {
			name, _ = os.Hostname()
		}
		if err := validateName(name); err != nil {
			return fail(err)
		}
		p := profile{Name: name, Router: args.Router, Firewall: args.Firewall, DisableSTUN: args.DisableSTUN}
		if _, err := rand.Read(p.Nonce[:]); err != nil {
			return fail(err)
		}
		if req.Method == "mesh.create" {
			if err := n.create(name, args.Masked, p); err != nil {
				return fail(err)
			}
		} else {
			code, err := Decode(args.Code, time.Now())
			if err != nil {
				return fail(err)
			}
			if code.Kind != "network" {
				return fail(errors.New("вставьте приглашение владельца сети"))
			}
			if len(code.Members) >= MaxMembers {
				return fail(errors.New("в сети уже 10 компьютеров"))
			}
			if _, ok := localMember(code, n.keys.IdentityPublic()); ok {
				return fail(errors.New("этот ПК уже в сети. Откройте сохранённое подключение"))
			}
			p.LocalIP, err = freeAddress(code)
			if err != nil {
				return fail(err)
			}
			p.Code, p.Pending = strings.TrimSpace(args.Code), true
			if err = n.replace(p, code); err != nil {
				return fail(err)
			}
		}
	case "mesh.accept":
		if n.p.Code == "" {
			return fail(errors.New("сначала создайте сеть или вставьте приглашение"))
		}
		code, err := Decode(args.Code, time.Now())
		if err != nil {
			return fail(err)
		}
		if err = n.accept(args.Code, code); err != nil {
			return fail(err)
		}
	case "mesh.code":
		if n.wg == nil || !n.scanned {
			return fail(errors.New("дождитесь поиска внешнего адреса"))
		}
		if n.owner() {
			code := n.roster
			code.Members = append([]Member(nil), code.Members...)
			code.Members[0].Endpoints = append([]netip.AddrPort(nil), n.endpoints...)
			code.Revision++
			code, text, err := n.sign(code)
			if err != nil {
				return fail(err)
			}
			p := n.p
			p.Code = text
			if err = n.save(p); err != nil {
				return fail(err)
			}
			n.p, n.roster = p, code
			return map[string]string{"code": text}, nil
		}
		public, err := n.keys.WireGuardPublic()
		if err != nil {
			return fail(err)
		}
		member := Member{Identity: n.keys.IdentityPublic(), WireGuard: public, Name: n.p.Name, IP: n.p.LocalIP, Endpoints: append([]netip.AddrPort(nil), n.endpoints...)}
		request := Code{Kind: "request", Session: n.roster.Session, Network: n.roster.Network, Owner: n.roster.Owner, Masked: n.roster.Masked, Revision: n.roster.Revision, Member: &member}
		_, text, err := n.sign(request)
		if err != nil {
			return fail(err)
		}
		return map[string]string{"code": text}, nil
	case "mesh.check":
		if n.wg == nil || n.p.Pending || n.p.Paused {
			return fail(errors.New("дождитесь подтверждения владельца"))
		}
		n.requestCheck()
	case "mesh.remove":
		if !n.owner() {
			return fail(errors.New("участников удаляет владелец сети"))
		}
		next := n.roster
		next.Members = nil
		found := false
		for _, m := range n.roster.Members {
			if memberID(m) == args.ID {
				if bytes.Equal(m.Identity, n.roster.Owner) {
					return fail(errors.New("владелец выходит через кнопку «Выйти из сети»"))
				}
				found = true
				continue
			}
			next.Members = append(next.Members, m)
		}
		if !found {
			return fail(errors.New("участник не найден"))
		}
		next.Revision++
		p := n.p
		var err error
		next, p.Code, err = n.sign(next)
		if err != nil {
			return fail(err)
		}
		if err = n.replace(p, next); err != nil {
			return fail(err)
		}
	case "mesh.reset":
		if err := n.save(profile{}); err != nil {
			return fail(err)
		}
		var stopErr error
		if n.wg != nil {
			stopErr = n.wg.Stop()
		}
		n.p, n.roster, n.wg = profile{}, Code{}, nil
		n.members, n.endpoints, n.scanned, n.detail = nil, nil, false, ""
		n.discovery, n.egress, n.interfaces = "", "", tunnel.DirectInterfaces{}
		if stopErr != nil {
			return fail(fmt.Errorf("профиль удалён, при остановке туннеля возникла ошибка: %w", stopErr))
		}
	default:
		return fail(errors.New("неизвестная команда сети"))
	}
	return n.status(), nil
}

func (n *node) status() any {
	state, detail := "idle", n.detail
	var members []memberStatus
	if n.p.Code != "" {
		state = "waiting"
		detail = "Добавляйте участников через запросы и обновлённый код владельца."
		if n.p.Pending {
			state, detail = "pending", "Скопируйте запрос владельцу. Затем вставьте обновлённый код сети с вашим допуском."
		}
		if n.wg == nil {
			state, detail = "revoked", "Этот ПК исключён из сети либо туннель остановлен."
		}
		if n.p.Paused {
			state, detail = "paused", "Соединения на этом ПК отключены. Нажмите «Подключиться», чтобы продолжить работу."
		}
		connected := 0
		for _, m := range n.roster.Members {
			s := n.members[memberID(m)]
			s.ID, s.Name, s.IP = memberID(m), m.Name, m.IP.String()
			if bytes.Equal(m.Identity, n.keys.IdentityPublic()) {
				s.State = "local"
			} else if n.wg == nil || n.p.Paused {
				s.State, s.RTT, s.Checking = "offline", 0, false
			} else if s.State == "" {
				s.State = "connecting"
			}
			if s.State == "connected" {
				connected++
			}
			members = append(members, s)
		}
		if connected > 0 && !n.p.Pending && !n.p.Paused && n.wg != nil {
			state = "connected"
			detail = fmt.Sprintf("Проверена связь с %d из %d участников.", connected, max(0, len(n.roster.Members)-1))
		}
		if n.detail != "" {
			detail = n.detail
		}
	}
	return struct {
		State     string         `json:"state"`
		Detail    string         `json:"detail"`
		LocalIP   string         `json:"local_ip"`
		Egress    string         `json:"egress"`
		Discovery string         `json:"discovery"`
		CodeReady bool           `json:"code_ready"`
		IsOwner   bool           `json:"is_owner"`
		Pending   bool           `json:"pending"`
		Paused    bool           `json:"paused"`
		Masked    bool           `json:"masked"`
		Members   []memberStatus `json:"members"`
	}{state, detail, n.p.LocalIP.String(), n.egress, n.discovery, n.scanned && n.wg != nil && !n.p.Paused, n.owner(), n.p.Pending, n.p.Paused, n.roster.Masked, members}
}

func (n *node) monitor(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var last *tunnel.Tunnel
	var nextScan time.Time
	var mapped netip.AddrPort
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.wake:
		}
		n.mu.Lock()
		wg, p, interfaces := n.wg, n.p, n.interfaces
		n.mu.Unlock()
		if wg == nil {
			continue
		}
		if wg != last {
			last, nextScan, mapped = wg, time.Time{}, netip.AddrPort{}
		}
		if time.Now().After(nextScan) {
			scan, cancel := context.WithTimeout(ctx, 9*time.Second)
			endpoints, detail, lease, interval := directpair.DiscoverEndpoints(scan, wg, p.Port, p.Router, p.DisableSTUN, p.Nonce, mapped, interfaces)
			cancel()
			mapped, nextScan = lease, time.Now().Add(interval)
			n.mu.Lock()
			if n.wg == wg {
				n.endpoints, n.discovery, n.scanned = endpoints, detail, true
			}
			n.mu.Unlock()
		}
		n.mu.Lock()
		if n.wg != wg || n.p.Pending {
			n.mu.Unlock()
			continue
		}
		var peers []Member
		for _, m := range n.roster.Members {
			if bytes.Equal(m.Identity, n.keys.IdentityPublic()) {
				continue
			}
			peers = append(peers, m)
			s := n.members[memberID(m)]
			s.Checking = true
			n.members[memberID(m)] = s
		}
		n.mu.Unlock()
		var workers sync.WaitGroup
		for _, member := range peers {
			workers.Add(1)
			go func(m Member) {
				defer workers.Done()
				probe, err := wg.Probe(memberID(m))
				stats, statsErr := wg.Stats(memberID(m))
				n.mu.Lock()
				defer n.mu.Unlock()
				if n.wg != wg {
					return
				}
				s := n.members[memberID(m)]
				s.Checking, s.LastProbe = false, time.Now()
				if statsErr == nil {
					s.LastHandshake = stats.LastHandshake
				}
				if err == nil {
					s.State, s.RTT, s.misses = "connected", float64(probe.RTT)/float64(time.Millisecond), 0
					ep, parse := netip.ParseAddrPort(stats.Endpoint)
					if parse == nil && directpair.PublicEndpoint(ep) && n.p.Learned[memberID(m)] != ep {
						p := n.p
						p.Learned = cloneEndpoints(p.Learned)
						p.Learned[memberID(m)] = ep
						if n.save(p) == nil {
							n.p = p
						}
					}
				} else {
					s.State, s.RTT = "connecting", 0
					s.misses++
					if s.misses >= 3 && len(m.Endpoints) > 0 {
						_ = wg.SetDirectEndpoint(memberID(m), m.Endpoints[(s.misses-3)%len(m.Endpoints)])
					}
				}
				n.members[memberID(m)] = s
			}(member)
		}
		workers.Wait()
	}
}
