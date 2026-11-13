//go:build windows

package directpair

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

	"directlan/internal/identity"
	"directlan/internal/localipc"
	"directlan/internal/platform"
	"directlan/internal/tunnel"
	"golang.org/x/sys/windows"
)

type profile struct {
	Session      string         `json:"session"`
	Network      netip.Prefix   `json:"network"`
	Host         bool           `json:"host"`
	Port         uint16         `json:"port"`
	Router       bool           `json:"router"`
	Firewall     bool           `json:"firewall"`
	DisableSTUN  bool           `json:"disable_stun,omitempty"`
	MappingNonce [12]byte       `json:"mapping_nonce"`
	RemoteCode   string         `json:"remote_code,omitempty"`
	LastEndpoint netip.AddrPort `json:"last_endpoint"`
}

type peerStatus struct {
	State         string    `json:"state"`
	Detail        string    `json:"detail"`
	Role          string    `json:"role,omitempty"`
	LocalIP       string    `json:"local_ip,omitempty"`
	PeerIP        string    `json:"peer_ip,omitempty"`
	Port          uint16    `json:"port,omitempty"`
	Endpoints     []string  `json:"endpoints,omitempty"`
	Discovery     string    `json:"discovery,omitempty"`
	CodeReady     bool      `json:"code_ready"`
	HasPeer       bool      `json:"has_peer"`
	PeerAddresses int       `json:"peer_addresses"`
	Egress        string    `json:"egress,omitempty"`
	Checking      bool      `json:"checking"`
	LastProbe     time.Time `json:"last_probe,omitzero"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	RTT           float64   `json:"rtt_ms,omitempty"`
}

type node struct {
	mu            sync.Mutex
	keys          identity.State
	path          string
	profile       profile
	remote        Code
	interfaces    tunnel.DirectInterfaces
	egress        string
	wg            *tunnel.Tunnel
	endpoints     []netip.AddrPort
	scanned       bool
	discovery     string
	state         string
	detail        string
	wake          chan struct{}
	checking      bool
	lastProbe     time.Time
	lastHandshake time.Time
	misses        int
	rtt           float64
}

func Run(ctx context.Context, identityPath, uiSID string) error {
	return RunWithHandler(ctx, identityPath, uiSID, nil)
}

func RunWithHandler(ctx context.Context, identityPath, uiSID string, extra localipc.Handler) error {
	keys, err := identity.LoadOrCreate(identityPath)
	if err != nil {
		return err
	}
	n := &node{keys: keys, path: identityPath + ".pair.json", state: "idle", detail: "Создайте соединение или вставьте приглашение с другого ПК.", wake: make(chan struct{}, 1)}
	var restore sync.Once
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); n.monitor(loopCtx) }()
	err = localipc.ServeNamed(ctx, localipc.PeerPipeName, uiSID, func(ctx context.Context, req localipc.Request) (any, *localipc.Error) {
		if req.Method == "system.ready" {
			return map[string]bool{"ready": true}, nil
		}
		if extra != nil && strings.HasPrefix(req.Method, "mesh.") {
			return extra(ctx, req)
		}
		restore.Do(func() {
			n.mu.Lock()
			defer n.mu.Unlock()
			if err := n.restore(); err != nil {
				n.detail = "Не удалось открыть сохранённую пару: " + err.Error()
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

func PhysicalInterfaces() (tunnel.DirectInterfaces, string) {
	return physicalInterfaces()
}

func DiscoverEndpoints(ctx context.Context, wg *tunnel.Tunnel, port uint16, router, disableSTUN bool, nonce [12]byte, previous netip.AddrPort, interfaces tunnel.DirectInterfaces) ([]netip.AddrPort, string, netip.AddrPort, time.Duration) {
	return discover(ctx, wg, profile{Port: port, Router: router, DisableSTUN: disableSTUN, MappingNonce: nonce}, previous, interfaces)
}

func DiscoverEndpointsWithAssessment(ctx context.Context, wg *tunnel.Tunnel, port uint16, router, disableSTUN bool, nonce [12]byte, previous netip.AddrPort, interfaces tunnel.DirectInterfaces) ([]netip.AddrPort, string, netip.AddrPort, time.Duration, MappingAssessment) {
	return discoverReport(ctx, wg, profile{Port: port, Router: router, DisableSTUN: disableSTUN, MappingNonce: nonce}, previous, interfaces)
}

func (n *node) restore() error {
	data, err := os.ReadFile(n.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var p profile
	if len(data) > 8192 || json.Unmarshal(data, &p) != nil {
		return errors.New("настройки пары повреждены")
	}
	if p.Session == "" {
		return nil
	}
	var remote Code
	if p.RemoteCode != "" {
		remote, err = Decode(p.RemoteCode, time.Time{})
		if err != nil {
			return err
		}
		if err = n.validateRemote(p, remote); err != nil {
			return err
		}
	}
	return n.start(p, remote)
}

func (n *node) save(p profile) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return identity.WritePrivateFile(n.path, data)
}

func overlayAddresses(p profile) (netip.Addr, netip.Addr) {
	host := p.Network.Addr().Next()
	guest := host.Next()
	if p.Host {
		return host, guest
	}
	return guest, host
}

func (n *node) start(p profile, remote Code) error {
	if n.wg != nil {
		return errors.New("сначала завершите текущую пару")
	}
	if p.MappingNonce == ([12]byte{}) {
		if _, err := rand.Read(p.MappingNonce[:]); err != nil {
			return err
		}
	}
	_, subnet, err := net.ParseCIDR(p.Network.String())
	if err != nil {
		return err
	}
	local, peer := overlayAddresses(p)
	interfaces, egress := physicalInterfaces()
	start := func(port uint16) (*tunnel.Tunnel, error) {
		wg, err := tunnel.NewDirect(n.keys.WireGuardPrivate, local.AsSlice(), subnet, port, interfaces)
		if err != nil {
			return nil, err
		}
		if err := wg.Start(); err != nil {
			return nil, err
		}
		return wg, nil
	}
	wg, err := start(p.Port)
	if p.Port != 0 && errors.Is(err, windows.WSAEADDRINUSE) {
		wg, err = start(0)
	}
	if err != nil {
		return err
	}
	p.Port, err = wg.DirectPort()
	if err == nil && len(remote.Identity) != 0 {
		endpoint := p.LastEndpoint
		if !PublicEndpoint(endpoint) {
			endpoint = netip.AddrPort{}
			if len(remote.Endpoints) > 0 {
				endpoint = remote.Endpoints[0]
			}
		}
		err = wg.AddDirectPeer("peer", remote.WireGuard, peer.AsSlice(), endpoint)
	}
	if err == nil {
		err = n.save(p)
	}
	if err != nil {
		_ = wg.Stop()
		return err
	}
	n.wg, n.profile, n.remote = wg, p, remote
	n.interfaces, n.egress = interfaces, egress
	n.state = "waiting"
	n.detail = "Скопируйте приглашение и передайте его второму ПК. Затем вставьте его ответ здесь."
	n.endpoints, n.scanned = nil, false
	n.discovery = "Ищем внешний адрес…"
	n.resetProbe()
	if len(remote.Identity) != 0 {
		n.state, n.detail = "connecting", "Оставьте DirectLAN запущенным на обоих ПК."
	}
	n.requestCheck()
	return nil
}

func newProfile() (profile, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return profile{}, err
	}
	p := profile{Session: hex.EncodeToString(random[:]), Host: true}
	for i := 0; i < 48; i++ {
		var ip [4]byte
		if _, err := rand.Read(ip[:]); err != nil {
			return profile{}, err
		}
		switch i % 3 {
		case 0:
			ip[0] = 10
		case 1:
			ip[0], ip[1] = 172, 16+ip[1]%16
		case 2:
			ip[0], ip[1] = 192, 168
		}
		p.Network = netip.PrefixFrom(netip.AddrFrom4(ip), 30).Masked()
		_, network, _ := net.ParseCIDR(p.Network.String())
		conflict, _, err := platform.RouteConflict(network, 0)
		if err != nil {
			return profile{}, err
		}
		if !conflict {
			return p, nil
		}
	}
	return profile{}, errors.New("не найдена свободная виртуальная подсеть")
}

func (n *node) validateRemote(p profile, remote Code) error {
	if remote.Session != p.Session || remote.Network != p.Network || remote.Host == p.Host || bytes.Equal(remote.Identity, n.keys.IdentityPublic()) {
		return errors.New("код относится к другой паре или создан на этом ПК")
	}
	if p.Host && !bytes.Equal(remote.For, n.keys.IdentityPublic()) {
		return errors.New("ответ создан для другого приглашения")
	}
	return nil
}

func (n *node) accept(text string, remote Code) error {
	p := n.profile
	if err := n.validateRemote(p, remote); err != nil {
		return err
	}
	first := len(n.remote.Identity) == 0
	if !first && (!bytes.Equal(n.remote.Identity, remote.Identity) || !bytes.Equal(n.remote.WireGuard, remote.WireGuard)) {
		return errors.New("код подписан другим устройством. Для смены участника создайте новую пару")
	}
	var endpoint netip.AddrPort
	if len(remote.Endpoints) != 0 {
		endpoint = remote.Endpoints[0]
	}
	if first {
		_, ip := overlayAddresses(p)
		if err := n.wg.AddDirectPeer("peer", remote.WireGuard, ip.AsSlice(), endpoint); err != nil {
			return err
		}
	}
	p.RemoteCode = text
	if endpoint.IsValid() {
		p.LastEndpoint = endpoint
	}
	if err := n.save(p); err != nil {
		if first {
			_ = n.wg.RemovePeer("peer")
		}
		return err
	}
	n.profile, n.remote = p, remote
	if !first && endpoint.IsValid() {
		if err := n.wg.SetDirectEndpoint("peer", endpoint); err != nil {
			return err
		}
	}
	n.state = "connecting"
	n.detail = "Проверяем зашифрованный канал…"
	n.resetProbe()
	n.requestCheck()
	return nil
}

func (n *node) handle(_ context.Context, req localipc.Request) (any, *localipc.Error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	fail := func(err error) (any, *localipc.Error) {
		return nil, &localipc.Error{Code: "DIRECT_PAIR", Message: err.Error()}
	}
	var args struct {
		Code        string `json:"code"`
		Router      bool   `json:"router"`
		Firewall    bool   `json:"firewall"`
		DisableSTUN bool   `json:"disable_stun"`
	}
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &args) != nil {
		return fail(errors.New("неверные параметры запроса"))
	}
	switch req.Method {
	case "peer.status":
		return n.status(), nil
	case "peer.check":
		if n.wg == nil || len(n.remote.Identity) == 0 {
			return fail(errors.New("сначала завершите обмен кодами"))
		}
		if !n.checking {
			n.checking = true
			n.requestCheck()
		}
		return n.status(), nil
	case "peer.create", "peer.join":
		var p profile
		var remote Code
		var err error
		if req.Method == "peer.create" {
			p, err = newProfile()
		} else {
			remote, err = Decode(args.Code, time.Now())
			if err == nil && !remote.Host {
				err = errors.New("здесь нужен код приглашения, а не ответ")
			}
			p = profile{Session: remote.Session, Network: remote.Network, RemoteCode: strings.TrimSpace(args.Code)}
			if err == nil {
				err = n.validateRemote(p, remote)
			}
		}
		if err != nil {
			return fail(err)
		}
		p.Router = args.Router
		p.Firewall = args.Firewall
		p.DisableSTUN = args.DisableSTUN
		if err := n.start(p, remote); err != nil {
			return fail(err)
		}
		return n.status(), nil
	case "peer.code":
		if n.wg == nil || !n.scanned {
			return fail(errors.New("дождитесь поиска адреса"))
		}
		wgKey, err := n.keys.WireGuardPublic()
		if err != nil {
			return fail(err)
		}
		code := Code{Session: n.profile.Session, Network: n.profile.Network, Host: n.profile.Host,
			Identity: n.keys.IdentityPublic(), WireGuard: wgKey, Endpoints: n.endpoints, Expires: time.Now().Add(30 * time.Minute)}
		if !code.Host {
			code.For = n.remote.Identity
		}
		encoded, err := Encode(code, ed25519.PrivateKey(n.keys.IdentityPrivate))
		if err != nil {
			return fail(err)
		}
		return map[string]string{"code": encoded}, nil
	case "peer.accept":
		if n.wg == nil {
			return fail(errors.New("сначала создайте пару или вставьте приглашение"))
		}
		remote, err := Decode(args.Code, time.Now())
		if err == nil {
			err = n.accept(strings.TrimSpace(args.Code), remote)
		}
		if err != nil {
			return fail(err)
		}
		return n.status(), nil
	case "peer.reset":
		if err := n.save(profile{}); err != nil {
			return fail(err)
		}
		if n.wg != nil {
			_ = n.wg.Stop()
		}
		n.wg, n.profile, n.remote = nil, profile{}, Code{}
		n.state, n.detail, n.discovery = "idle", "Создайте соединение или вставьте приглашение с другого ПК.", ""
		n.endpoints, n.scanned = nil, false
		n.resetProbe()
		return n.status(), nil
	default:
		return fail(errors.New("неизвестная операция DirectLAN"))
	}
}

func (n *node) status() peerStatus {
	s := peerStatus{
		State: n.state, Detail: n.detail, Discovery: n.discovery, RTT: n.rtt,
		Checking: n.checking, LastProbe: n.lastProbe, LastHandshake: n.lastHandshake,
	}
	if n.wg != nil {
		local, peer := overlayAddresses(n.profile)
		s.LocalIP, s.PeerIP = local.String(), peer.String()
		s.Port = n.profile.Port
		s.CodeReady = n.scanned
		s.HasPeer = len(n.remote.Identity) != 0
		s.PeerAddresses = len(n.remote.Endpoints)
		s.Egress = n.egress
		s.Role = "guest"
		if n.profile.Host {
			s.Role = "host"
		}
		for _, address := range n.endpoints {
			s.Endpoints = append(s.Endpoints, address.String())
		}
	}
	return s
}

func (n *node) resetProbe() {
	n.checking, n.lastProbe, n.lastHandshake, n.misses, n.rtt = false, time.Time{}, time.Time{}, 0, 0
}

func (n *node) requestCheck() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func (n *node) monitor(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last *tunnel.Tunnel
	var mapped netip.AddrPort
	var nextScan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.wake:
		}
		n.mu.Lock()
		wg, p, interfaces := n.wg, n.profile, n.interfaces
		n.mu.Unlock()
		if wg == nil {
			continue
		}
		if last != wg {
			last, nextScan, mapped = wg, time.Time{}, netip.AddrPort{}
		}
		if time.Now().After(nextScan) {
			scanCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
			endpoints, detail, lease, interval := discover(scanCtx, wg, p, mapped, interfaces)
			cancel()
			mapped, nextScan = lease, time.Now().Add(interval)
			n.mu.Lock()
			if n.wg == wg {
				n.endpoints, n.discovery, n.scanned = endpoints, detail, true
			}
			n.mu.Unlock()
		}
		n.mu.Lock()
		if n.wg != wg || len(n.remote.Identity) == 0 {
			n.mu.Unlock()
			continue
		}
		p, remote := n.profile, n.remote
		n.checking = true
		n.mu.Unlock()

		probe, err := wg.Probe("peer")
		stats, statsErr := wg.Stats("peer")
		n.mu.Lock()
		if n.wg == wg && n.profile.RemoteCode == p.RemoteCode {
			n.checking, n.lastProbe = false, time.Now()
			if statsErr == nil {
				n.lastHandshake = stats.LastHandshake
			}
			if err == nil {
				n.misses = 0
				n.lastHandshake = probe.LastHandshake
				n.state, n.detail = "connected", "Прямой туннель WireGuard проверен в обе стороны."
				n.rtt = float64(probe.RTT) / float64(time.Millisecond)
				endpoint, parseErr := netip.ParseAddrPort(stats.Endpoint)
				if statsErr == nil && parseErr == nil && PublicEndpoint(endpoint) && endpoint != n.profile.LastEndpoint {
					updated := n.profile
					updated.LastEndpoint = endpoint
					if n.save(updated) == nil {
						n.profile = updated
					}
				}
			} else {
				n.misses++
				n.state, n.rtt = "connecting", 0
				n.detail = "WireGuard ждёт ответа второго ПК."
				if n.misses >= 3 {
					n.detail = "WireGuard пока не получил подтверждённого ответа. Проверьте, что оба ПК запущены и обменялись свежими кодами."
					if len(remote.Endpoints) > 1 || len(remote.Endpoints) == 1 && p.LastEndpoint != remote.Endpoints[0] {
						_ = wg.SetDirectEndpoint("peer", remote.Endpoints[(n.misses-3)%len(remote.Endpoints)])
					}
				}
				if !n.lastHandshake.IsZero() {
					n.detail = "WireGuard уже обменялся ключами. Текущая проверка через туннель не получила ответа."
				} else if len(remote.Endpoints) == 0 && !PublicEndpoint(p.LastEndpoint) {
					n.detail = "В полученном коде нет внешнего адреса второго ПК. Попросите прислать новый код после завершения поиска адреса."
				}
				if n.lastHandshake.IsZero() && n.scanned && len(n.endpoints) == 0 && len(remote.Endpoints) == 0 && !PublicEndpoint(p.LastEndpoint) {
					n.state = "unreachable"
					n.detail = "Внешние UDP-адреса не найдены. Обменяйтесь свежими кодами после окончания поиска на обоих ПК."
				}
			}
		}
		n.mu.Unlock()
		if err == nil {
			ticker.Reset(5 * time.Second)
		} else {
			ticker.Reset(time.Second)
		}
	}
}

func discover(ctx context.Context, wg *tunnel.Tunnel, p profile, previous netip.AddrPort, interfaces tunnel.DirectInterfaces) ([]netip.AddrPort, string, netip.AddrPort, time.Duration) {
	endpoints, detail, mapped, interval, _ := discoverReport(ctx, wg, p, previous, interfaces)
	return endpoints, detail, mapped, interval
}

func discoverReport(ctx context.Context, wg *tunnel.Tunnel, p profile, previous netip.AddrPort, interfaces tunnel.DirectInterfaces) ([]netip.AddrPort, string, netip.AddrPort, time.Duration, MappingAssessment) {
	interval := 35 * time.Second
	assessment := MappingAssessment{Result: "not_tested"}
	var endpoints []netip.AddrPort
	add := func(ep netip.AddrPort) {
		if !PublicEndpoint(ep) || len(endpoints) >= 4 {
			return
		}
		for _, known := range endpoints {
			if known == ep {
				return
			}
		}
		endpoints = append(endpoints, ep)
	}
	adapters, _ := platform.PhysicalCandidates()
	var local, gateway netip.Addr
	for _, adapter := range adapters {
		if !adapter.IsHardware() {
			continue
		}
		for _, raw := range adapter.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			if ip.Is4() && interfaces.IPv4 != 0 && adapter.Index != interfaces.IPv4 ||
				ip.Is6() && interfaces.IPv6 != 0 && adapter.IPv6Index != interfaces.IPv6 {
				continue
			}
			add(netip.AddrPortFrom(ip, p.Port))
			if local.IsValid() || !ip.Is4() || !ip.IsPrivate() {
				continue
			}
			for _, rawGateway := range adapter.Gateways {
				g, err := netip.ParseAddr(rawGateway)
				if err == nil && g.Is4() && g.IsPrivate() {
					local, gateway = ip, g
					break
				}
			}
		}
	}
	var mapped netip.AddrPort
	detail := "Публичный адрес не найден. Этот ПК ещё может сам подключиться к доступному второму ПК."
	if p.Router && local.IsValid() {
		routerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lease, err := requestMapping(routerCtx, local, gateway, p.Port, p.MappingNonce, previous)
		if err != nil {
			lease, err = upnpMapping(routerCtx, local, gateway, p.Port, p.MappingNonce)
		}
		cancel()
		if err == nil && lease.endpoint.IsValid() && !PublicEndpoint(lease.endpoint) {
			detail = "Роутер вернул частный адрес. Возможно, подключение использует CGNAT или двойной NAT."
		}
		if err == nil && lease.lifetime > 0 {
			mapped = lease.endpoint
			add(mapped)
			interval = min(interval, max(5*time.Second, lease.lifetime/2))
		}
	}
	if len(endpoints) > 0 {
		detail = fmt.Sprintf("Найдено адресов: %d. Доступность проверяется при подключении второго ПК.", len(endpoints))
	}
	if !p.DisableSTUN {
		stunCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		observed, report := discoverSTUNReport(stunCtx, wg)
		cancel()
		assessment = report
		if len(observed) > 0 {
			// Retain both sampled mappings even when a physical interface has
			// many public addresses. Codes remain limited to four candidates.
			known := endpoints
			endpoints = nil
			// An explicit router lease remains the first candidate; STUN can
			// observe a different mapping while contacting its own destination.
			add(mapped)
			for _, endpoint := range observed {
				add(endpoint)
			}
			for _, endpoint := range known {
				add(endpoint)
			}
			if len(known) == 0 {
				detail = "STUN нашёл внешний UDP-адрес. Доступность проверяется при подключении второго ПК."
			} else {
				detail = fmt.Sprintf("Найдено адресов: %d. Доступность проверяется при подключении второго ПК.", len(endpoints))
			}
			interval = min(interval, 15*time.Second)
		} else {
			detail += " Ответа от STUN нет."
		}
		if assessment.Result == "different_observations" {
			detail += " Внешний UDP-адрес или порт меняется между STUN-серверами; это может мешать прямому соединению."
		}
	}
	return endpoints, detail, mapped, interval, assessment
}

func discoverSTUN(ctx context.Context, wg *tunnel.Tunnel) netip.AddrPort {
	observed, _ := discoverSTUNReport(ctx, wg)
	if len(observed) != 0 {
		return observed[0]
	}
	return netip.AddrPort{}
}
