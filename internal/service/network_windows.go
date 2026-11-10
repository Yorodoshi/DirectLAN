//go:build windows

package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"directlan/internal/coordinator"
	"directlan/internal/localipc"
	"directlan/internal/peerice"
	"directlan/internal/platform"
	"directlan/internal/tunnel"
)

type networkState struct {
	mu     sync.Mutex
	key    string
	links  map[string]*peerLink
	tunnel *tunnel.Tunnel
}
type peerLink struct {
	member     coordinator.Member
	offers     chan coordinator.Signal
	cancel     context.CancelFunc
	active     atomic.Bool
	lastRemote uint64
}

func (s *Service) stopNetwork() {
	s.network.mu.Lock()
	for _, link := range s.network.links {
		link.active.Store(false)
		link.cancel()
	}
	s.network.links = nil
	if s.network.tunnel != nil {
		_ = s.network.tunnel.Stop()
		s.network.tunnel = nil
	}
	s.network.key = ""
	s.network.mu.Unlock()
	s.mu.Lock()
	s.peerStatus = make(map[string]PeerStatus)
	s.mu.Unlock()
}

func (s *Service) ensureNetwork(ctx context.Context) {
	s.mu.RLock()
	if s.snapshot == nil {
		s.mu.RUnlock()
		return
	}
	snapshot := *s.snapshot
	adapterID := s.identity.AdapterID
	selfID := ownDeviceID(s.identity)
	s.mu.RUnlock()
	if adapterID == "" {
		return
	}
	adapters, err := platform.PhysicalCandidates()
	if err != nil {
		return
	}
	var chosen *platform.Adapter
	var source net.IP
	for _, a := range adapters {
		if a.ID == adapterID {
			copy := a
			chosen = &copy
			for _, raw := range a.Addresses {
				ip := net.ParseIP(raw)
				if ip.To4() != nil {
					source = ip
					break
				}
			}
			break
		}
	}
	if chosen == nil || source == nil {
		s.stopNetwork()
		return
	}
	key := snapshot.NetworkID + ":" + chosen.ID + ":" + source.String()
	s.network.mu.Lock()
	if s.network.key != "" && s.network.key != key {
		s.network.mu.Unlock()
		s.stopNetwork()
		s.network.mu.Lock()
	}
	s.network.key = key
	if s.network.tunnel != nil {
		if err := s.network.tunnel.CheckRoutes(); err != nil {
			s.network.mu.Unlock()
			s.stopNetwork()
			s.mu.Lock()
			s.eventLocked("error", err.Error())
			s.mu.Unlock()
			return
		}
	}
	if s.network.links == nil {
		s.network.links = make(map[string]*peerLink)
	}
	allowed := make(map[string]coordinator.Member)
	for _, member := range snapshot.Members {
		if member.DeviceID != selfID {
			allowed[member.DeviceID] = member
		}
	}
	for id, link := range s.network.links {
		member, ok := allowed[id]
		if !ok || member.PublicKey != link.member.PublicKey || member.OverlayIP != link.member.OverlayIP {
			link.active.Store(false)
			link.cancel()
			delete(s.network.links, id)
			if s.network.tunnel != nil {
				_ = s.network.tunnel.RemovePeer(id)
			}
		}
	}
	for id, member := range allowed {
		if s.network.links[id] != nil {
			continue
		}
		linkCtx, cancel := context.WithCancel(ctx)
		link := &peerLink{member: member, offers: make(chan coordinator.Signal, 1), cancel: cancel}
		link.active.Store(true)
		s.network.links[id] = link
		go s.runPeer(linkCtx, link, snapshot, *chosen, source, selfID)
	}
	s.network.mu.Unlock()
	s.mu.Lock()
	s.adapter = chosen
	s.mu.Unlock()
}

func (s *Service) setLinkStatus(link *peerLink, state, transport string, rtt time.Duration, problem error) {
	if !link.active.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerStatus[link.member.DeviceID] = PeerStatus{State: state, Egress: "Unknown", Transport: transport, RTTMs: float64(rtt) / float64(time.Millisecond)}
	if problem != nil {
		s.eventLocked("error", fmt.Sprintf("Канал %s: %v", link.member.DeviceID[:8], problem))
	}
}

func waitContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Service) directTransport(ctx context.Context, link *peerLink, snapshot coordinator.Snapshot, adapter platform.Adapter, source net.IP, selfID string) (net.Conn, func(), error) {
	session, err := peerice.New(peerice.Config{InterfaceName: adapter.Name, LocalIP: source, STUNURLs: s.cfg.STUNURLs})
	if err != nil {
		return nil, nil, err
	}
	closeSession := func() { _ = session.Close() }
	offer, err := session.GatherContext(ctx)
	if err != nil {
		closeSession()
		return nil, nil, err
	}
	_, err = s.api.SendSignal(ctx, snapshot.NetworkID, link.member.DeviceID, coordinator.Signal{ICEUfrag: offer.Ufrag, ICEPwd: offer.Password, Candidates: offer.Candidates, ExpiresAt: offer.ExpiresAt, Generation: uint64(time.Now().UnixNano())})
	if err != nil {
		closeSession()
		return nil, nil, err
	}
	var remote coordinator.Signal
	select {
	case remote = <-link.offers:
	case <-ctx.Done():
		closeSession()
		return nil, nil, ctx.Err()
	}
	conn, err := session.Connect(ctx, peerice.Offer{Ufrag: remote.ICEUfrag, Password: remote.ICEPwd, Candidates: remote.Candidates, ExpiresAt: remote.ExpiresAt}, selfID < link.member.DeviceID)
	if err != nil {
		closeSession()
		return nil, nil, err
	}
	return conn, closeSession, nil
}

func (s *Service) runPeer(ctx context.Context, link *peerLink, snapshot coordinator.Snapshot, adapter platform.Adapter, source net.IP, selfID string) {
	var localIP string
	for _, member := range snapshot.Members {
		if member.DeviceID == selfID {
			localIP = member.OverlayIP
		}
	}
	public, err := base64.StdEncoding.DecodeString(link.member.PublicKey)
	if err != nil || len(public) != 32 {
		return
	}
	for ctx.Err() == nil && link.active.Load() {
		s.setLinkStatus(link, "Connecting", "", 0, nil)
		var conn net.Conn
		var cleanup func()
		mode := "Direct"
		if s.cfg.Transport != "https" {
			directCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			conn, cleanup, err = s.directTransport(directCtx, link, snapshot, adapter, source, selfID)
			cancel()
		}
		if conn == nil && s.cfg.Transport != "direct" && ctx.Err() == nil {
			mode = "Relay"
			dialer, dialErr := platform.BoundTCPDialer(adapter, source)
			if dialErr == nil {
				relayCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				conn, err = s.api.Relay(relayCtx, snapshot.NetworkID, link.member.DeviceID, dialer, s.cfg.Padding)
				cancel()
				if conn != nil {
					cleanup = func() { _ = conn.Close() }
				}
			} else {
				err = dialErr
			}
		}
		if conn == nil {
			s.setLinkStatus(link, "Blocked", "", 0, err)
			if !waitContext(ctx, 10*time.Second) {
				return
			}
			continue
		}
		wg, installErr := s.installTransport(link, snapshot, localIP, public, conn)
		if installErr != nil {
			cleanup()
			s.setLinkStatus(link, "Blocked", mode, 0, installErr)
			if !waitContext(ctx, 15*time.Second) {
				return
			}
			continue
		}
		verified := false
		for attempt := 0; attempt < 3 && ctx.Err() == nil; attempt++ {
			probe, probeErr := wg.Probe(link.member.DeviceID)
			if probeErr == nil {
				s.setLinkStatus(link, mode, mode, probe.RTT, nil)
				verified = true
				break
			}
			err = probeErr
			if !waitContext(ctx, time.Second) {
				break
			}
		}
		if verified {
			misses := 0
			for waitContext(ctx, 5*time.Second) && link.active.Load() {
				probe, probeErr := wg.Probe(link.member.DeviceID)
				if probeErr != nil {
					misses++
					err = probeErr
					if misses >= 3 {
						break
					}
				} else {
					misses = 0
					s.setLinkStatus(link, mode, mode, probe.RTT, nil)
				}
			}
		}
		s.removeTransport(link)
		cleanup()
		if ctx.Err() != nil {
			return
		}
		s.setLinkStatus(link, "Reconnecting", mode, 0, err)
		if !waitContext(ctx, time.Second) {
			return
		}
	}
}

func (s *Service) installTransport(link *peerLink, snapshot coordinator.Snapshot, localIP string, public []byte, conn net.Conn) (*tunnel.Tunnel, error) {
	s.network.mu.Lock()
	defer s.network.mu.Unlock()
	if !link.active.Load() {
		return nil, context.Canceled
	}
	if s.network.tunnel == nil {
		_, prefix, err := net.ParseCIDR(snapshot.NetworkCIDR)
		if err != nil {
			return nil, err
		}
		s.mu.RLock()
		private := append([]byte(nil), s.identity.WireGuardPrivate...)
		s.mu.RUnlock()
		wg, err := tunnel.New(private, net.ParseIP(localIP), prefix)
		if err != nil {
			return nil, err
		}
		if err = wg.Start(); err != nil {
			_ = wg.Stop()
			return nil, err
		}
		s.network.tunnel = wg
	}
	if err := s.network.tunnel.AddPeer(link.member.DeviceID, public, net.ParseIP(link.member.OverlayIP), conn); err != nil {
		return nil, err
	}
	return s.network.tunnel, nil
}

func (s *Service) removeTransport(link *peerLink) {
	s.network.mu.Lock()
	defer s.network.mu.Unlock()
	if s.network.tunnel != nil && link.active.Load() {
		_ = s.network.tunnel.RemovePeer(link.member.DeviceID)
	}
}

func (s *Service) signalLoop(ctx context.Context) {
	var after uint64
	var currentNetwork string
	for ctx.Err() == nil {
		s.mu.RLock()
		networkID := s.identity.NetworkID
		revision := s.identity.Revision
		ready := s.snapshot != nil
		s.mu.RUnlock()
		if networkID == "" || !ready {
			if !waitContext(ctx, time.Second) {
				return
			}
			continue
		}
		if currentNetwork != networkID {
			after = 0
			currentNetwork = networkID
		}
		result, err := s.api.Signals(ctx, networkID, after, revision, 20)
		if err != nil {
			if !waitContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		for _, signal := range result.Signals {
			if signal.Seq > after {
				after = signal.Seq
			}
			if !time.Now().Before(signal.ExpiresAt) {
				continue
			}
			s.network.mu.Lock()
			link := s.network.links[signal.FromDeviceID]
			if link != nil && signal.Generation > link.lastRemote {
				link.lastRemote = signal.Generation
				select {
				case link.offers <- signal:
				default:
					select {
					case <-link.offers:
					default:
					}
					select {
					case link.offers <- signal:
					default:
					}
				}
			}
			s.network.mu.Unlock()
		}
	}
}

func (s *Service) checkConnection(id string) (any, *localipc.Error) {
	s.network.mu.Lock()
	wg := s.network.tunnel
	link := s.network.links[id]
	s.network.mu.Unlock()
	if wg == nil || link == nil {
		return nil, bad("NOT_CONNECTED", "Канал ещё не установлен", "Выберите физический адаптер и проверьте доступность второго ПК")
	}
	probe, err := wg.Probe(id)
	if err != nil {
		return nil, bad("PROBE_FAILED", err.Error(), "Проверьте доступность пира и узкое правило Firewall для UDP 41985 на виртуальном интерфейсе")
	}
	return map[string]any{"rtt_ms": float64(probe.RTT) / float64(time.Millisecond), "message": "Подтверждены WireGuard-handshake и двусторонний обмен через виртуальные IP; внешний выход остаётся Unknown до независимой проверки"}, nil
}
