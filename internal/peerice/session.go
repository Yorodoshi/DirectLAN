package peerice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
)

// Offer contains only short-lived ICE signaling data. It must be delivered
// through an authenticated channel, after the remote device key is approved.
type Offer struct {
	Ufrag      string    `json:"ice_ufrag"`
	Password   string    `json:"ice_pwd"`
	Candidates []string  `json:"candidates"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (o Offer) Validate(now time.Time) error {
	if o.Ufrag == "" || o.Password == "" || len(o.Candidates) == 0 || len(o.Candidates) > 32 {
		return errors.New("invalid ICE offer")
	}
	if o.ExpiresAt.IsZero() || !now.Before(o.ExpiresAt) || o.ExpiresAt.After(now.Add(5*time.Minute)) {
		return errors.New("expired or unreasonably long ICE offer")
	}
	for _, raw := range o.Candidates {
		if len(raw) > 1024 {
			return errors.New("ICE candidate too long")
		}
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil || candidate.Type() == ice.CandidateTypeRelay {
			return errors.New("invalid direct ICE candidate")
		}
	}
	return nil
}

type Config struct {
	InterfaceName string
	LocalIP       net.IP
	STUNURLs      []string
}

type Session struct {
	mu      sync.Mutex
	agent   *ice.Agent
	mux     *ice.UniversalUDPMuxDefault
	socket  *net.UDPConn
	conn    *ice.Conn
	closed  bool
	localIP net.IP
	ifName  string
}

// New creates an ICE agent confined to one explicitly chosen interface and
// local address. Failure to bind that interface aborts instead of silently
// using a VPN or another system route.
func New(cfg Config) (_ *Session, err error) {
	if cfg.InterfaceName == "" || cfg.LocalIP == nil {
		return nil, errors.New("physical interface and local IP are required")
	}
	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, errors.New("interface is down or loopback")
	}
	if !hasAddress(iface, cfg.LocalIP) {
		return nil, errors.New("selected IP is not assigned to interface")
	}
	udpNet, networkType := "udp4", ice.NetworkTypeUDP4
	if cfg.LocalIP.To4() == nil {
		udpNet, networkType = "udp6", ice.NetworkTypeUDP6
	}
	socket, err := net.ListenUDP(udpNet, &net.UDPAddr{IP: cfg.LocalIP, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen on selected IP: %w", err)
	}
	defer func() {
		if err != nil {
			_ = socket.Close()
		}
	}()
	if err = bindSocketToInterface(socket, iface.Index, cfg.LocalIP.To4() == nil); err != nil {
		return nil, fmt.Errorf("bind socket to interface: %w", err)
	}
	mux := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: socket})
	options := []ice.AgentOption{
		ice.WithNetworkTypes([]ice.NetworkType{networkType}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}),
		ice.WithUDPMux(mux),
		ice.WithUDPMuxSrflx(mux),
		ice.WithInterfaceFilter(func(name string) bool { return name == cfg.InterfaceName }),
		ice.WithIPFilter(func(ip net.IP) bool { return ip.Equal(cfg.LocalIP) }),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled),
	}
	if len(cfg.STUNURLs) > 0 {
		urls := make([]*stun.URI, 0, len(cfg.STUNURLs))
		for _, raw := range cfg.STUNURLs {
			uri, parseErr := stun.ParseURI(strings.TrimSpace(raw))
			if parseErr != nil || uri.Scheme != stun.SchemeTypeSTUN {
				_ = mux.Close()
				return nil, fmt.Errorf("invalid STUN URL %q", raw)
			}
			urls = append(urls, uri)
		}
		options = append(options, ice.WithUrls(urls))
	}
	agent, err := ice.NewAgentWithOptions(options...)
	if err != nil {
		_ = mux.Close()
		return nil, fmt.Errorf("create ICE agent: %w", err)
	}
	return &Session{agent: agent, mux: mux, socket: socket, localIP: append(net.IP(nil), cfg.LocalIP...), ifName: cfg.InterfaceName}, nil
}

func hasAddress(iface *net.Interface, want net.IP) bool {
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.Equal(want) {
			return true
		}
	}
	return false
}

func (s *Session) Gather() (Offer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.GatherContext(ctx)
}

func (s *Session) GatherContext(ctx context.Context) (Offer, error) {
	done := make(chan struct{})
	var once sync.Once
	if err := s.agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			once.Do(func() { close(done) })
		}
	}); err != nil {
		return Offer{}, err
	}
	if err := s.agent.GatherCandidates(); err != nil {
		return Offer{}, fmt.Errorf("gather ICE candidates: %w", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		return Offer{}, ctx.Err()
	}
	ufrag, password, err := s.agent.GetLocalUserCredentials()
	if err != nil {
		return Offer{}, err
	}
	candidates, err := s.agent.GetLocalCandidates()
	if err != nil {
		return Offer{}, err
	}
	offer := Offer{Ufrag: ufrag, Password: password, ExpiresAt: time.Now().Add(2 * time.Minute)}
	for _, c := range candidates {
		if c.Type() != ice.CandidateTypeRelay {
			offer.Candidates = append(offer.Candidates, c.Marshal())
		}
	}
	if len(offer.Candidates) == 0 {
		return Offer{}, errors.New("no direct ICE candidates on selected interface")
	}
	return offer, nil
}

// Connect starts ICE checks. Exactly one side must be controlling. The caller
// must authenticate the offer sender and compare its WireGuard public key to
// the approved membership before attaching the returned connection.
func (s *Session) Connect(ctx context.Context, remote Offer, controlling bool) (*ice.Conn, error) {
	if err := remote.Validate(time.Now()); err != nil {
		return nil, err
	}
	for _, raw := range remote.Candidates {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			return nil, err
		}
		if err = s.agent.AddRemoteCandidate(candidate); err != nil {
			return nil, err
		}
	}
	var conn *ice.Conn
	var err error
	if controlling {
		conn, err = s.agent.Dial(ctx, remote.Ufrag, remote.Password)
	} else {
		conn, err = s.agent.Accept(ctx, remote.Ufrag, remote.Password)
	}
	if err != nil {
		return nil, err
	}
	pair, err := s.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil || pair.Local == nil || pair.Remote == nil || pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		_ = conn.Close()
		return nil, errors.New("ICE did not select a direct candidate pair")
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	return conn, nil
}

func (s *Session) SelectedPair() (*ice.CandidatePair, error) {
	return s.agent.GetSelectedCandidatePair()
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	err := s.agent.Close()
	_ = s.mux.Close()
	_ = s.socket.Close()
	return err
}
