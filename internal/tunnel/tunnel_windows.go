//go:build windows

// Package tunnel owns the Windows L3 adapter and the WireGuard device for one
// DirectLAN group. It never installs a default route or changes DNS settings.
package tunnel

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"directlan/internal/icebind"
	"directlan/internal/platform"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	OverlayMTU  = 1280
	ProbePort   = 41985
	probePrefix = "DLANP1:"
	probeWait   = 5 * time.Second
)

var (
	ErrStopped       = errors.New("tunnel has been stopped")
	ErrNotStarted    = errors.New("tunnel is not started")
	ErrUnknownPeer   = errors.New("unknown tunnel peer")
	ErrRouteConflict = errors.New("overlay route conflicts with an existing route")
	ErrProbeFailed   = errors.New("authenticated overlay probe failed")
)

type Tunnel struct {
	mu            sync.Mutex
	privateKey    [32]byte
	secureContext string
	masked        bool
	mtu           uint32
	localIP       net.IP
	groupCIDR     *net.IPNet
	peers         map[string]*peer
	echoPeers     sync.Map
	policy        *packetPolicy

	adapter    tun.Device
	device     *device.Device
	bind       *icebind.Bind
	direct     *stunBind
	interfaces DirectInterfaces
	native     bool
	port       uint16
	luid       uint64
	ifIndex    uint32
	address    *windows.MibUnicastIpAddressRow
	echo       *net.UDPConn
	echoDone   chan struct{}
	running    bool
	stopped    bool
}

type peer struct {
	id        string
	publicKey [32]byte
	ip        net.IP
	conn      net.Conn
	route     *windows.MibIpForwardRow2
	attached  bool
	endpoint  netip.AddrPort
	crypto    *peerCrypto
}

type PeerStats struct {
	PeerID        string    `json:"peer_id"`
	VirtualIP     string    `json:"virtual_ip"`
	LastHandshake time.Time `json:"last_handshake"`
	TxBytes       uint64    `json:"tx_bytes"`
	RxBytes       uint64    `json:"rx_bytes"`
	Endpoint      string    `json:"endpoint,omitempty"`
}

type ProbeResult struct {
	PeerID        string        `json:"peer_id"`
	RTT           time.Duration `json:"rtt"`
	LastHandshake time.Time     `json:"last_handshake"`
	TxBytes       uint64        `json:"tx_bytes"`
	RxBytes       uint64        `json:"rx_bytes"`
}

// New validates the private key and the private IPv4 overlay prefix. It does
// not create an adapter or change the host network configuration.
func New(privateKey []byte, overlayIP net.IP, networkCIDR *net.IPNet) (*Tunnel, error) {
	if len(privateKey) != 32 || bytes.Equal(privateKey, make([]byte, 32)) {
		return nil, fmt.Errorf("WireGuard private key must be 32 nonzero bytes")
	}
	ip := overlayIP.To4()
	if ip == nil || !ip.IsPrivate() {
		return nil, fmt.Errorf("overlay IP must be a private IPv4 address")
	}
	if networkCIDR == nil || networkCIDR.IP.To4() == nil {
		return nil, fmt.Errorf("overlay prefix must be IPv4")
	}
	ones, bits := networkCIDR.Mask.Size()
	if bits != 32 || ones < 8 || ones > 30 {
		return nil, fmt.Errorf("overlay prefix length must be 8..30")
	}
	groupIP := networkCIDR.IP.To4().Mask(networkCIDR.Mask)
	group := &net.IPNet{IP: append(net.IP(nil), groupIP...), Mask: append(net.IPMask(nil), networkCIDR.Mask...)}
	if !group.Contains(ip) || unusableHost(ip, group) {
		return nil, fmt.Errorf("overlay IP must be a usable host within %s", group)
	}
	t := &Tunnel{
		localIP:   append(net.IP(nil), ip...),
		groupCIDR: group,
		peers:     make(map[string]*peer),
		mtu:       OverlayMTU,
	}
	copy(t.privateKey[:], privateKey)
	t.policy = newPolicy(ip)
	return t, nil
}

// AddPeer transfers ownership of iceConn after validation. The connection
// must already be an ICE selected-pair datagram connection. On an installation
// failure, the connection is closed and no route or WireGuard peer remains.
func (t *Tunnel) AddPeer(peerID string, publicKey []byte, peerIP net.IP, iceConn net.Conn) error {
	if t.native || iceConn == nil {
		return fmt.Errorf("invalid ICE transport")
	}
	return t.addPeer(peerID, publicKey, peerIP, iceConn, netip.AddrPort{}, nil)
}

func (t *Tunnel) addPeer(peerID string, publicKey []byte, peerIP net.IP, transport net.Conn, endpoint netip.AddrPort, keys *peerCrypto) error {
	if !validPeerID(peerID) || len(publicKey) != 32 || bytes.Equal(publicKey, make([]byte, 32)) {
		return fmt.Errorf("invalid peer ID, public key, or ICE connection")
	}
	ip := peerIP.To4()
	if ip == nil || !t.groupCIDR.Contains(ip) || unusableHost(ip, t.groupCIDR) || ip.Equal(t.localIP) {
		return fmt.Errorf("peer IP must be a distinct usable address in %s", t.groupCIDR)
	}
	var key [32]byte
	copy(key[:], publicKey)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return ErrStopped
	}
	if len(t.peers) >= 9 {
		return fmt.Errorf("group limit of 10 devices reached")
	}
	if t.peers[peerID] != nil {
		return fmt.Errorf("peer ID already exists")
	}
	for _, existing := range t.peers {
		if existing.ip.Equal(ip) || existing.publicKey == key {
			return fmt.Errorf("peer IP or key already exists")
		}
	}
	p := &peer{id: peerID, publicKey: key, ip: append(net.IP(nil), ip...), conn: transport, endpoint: endpoint, crypto: keys}
	if t.running {
		if err := t.installPeerLocked(p); err != nil {
			if transport != nil {
				_ = transport.Close()
			}
			return err
		}
	}
	t.peers[peerID] = p
	t.echoPeers.Store(p.ip.String(), true)
	t.policy.setPeer(p.ip, true)
	return nil
}

// Start creates a unique Wintun adapter, a /32 local address and one /32
// route per peer. Any failure rolls back created entries and closes the tunnel.
func (t *Tunnel) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return ErrStopped
	}
	if t.running {
		return nil
	}
	if conflict, route, err := platform.RouteConflict(t.groupCIDR, 0); err != nil {
		return fmt.Errorf("inspect overlay routes: %w", err)
	} else if conflict {
		return fmt.Errorf("%w: %s", ErrRouteConflict, route)
	}
	name, err := newAdapterName()
	if err != nil {
		return err
	}
	adapter, err := tun.CreateTUN(name, int(t.mtu))
	if err != nil {
		return fmt.Errorf("create Wintun adapter (signed wintun.dll and administrator service required): %w", err)
	}
	t.adapter = adapter
	if luidProvider, ok := adapter.(interface{ LUID() uint64 }); ok {
		t.luid = luidProvider.LUID()
	}
	if t.luid == 0 {
		return t.startFailureLocked(fmt.Errorf("Wintun adapter has no LUID"))
	}
	if t.ifIndex, err = interfaceIndex(t.luid); err != nil {
		return t.startFailureLocked(err)
	}
	if conflict, route, err := platform.RouteConflict(t.groupCIDR, t.ifIndex); err != nil {
		return t.startFailureLocked(fmt.Errorf("inspect overlay routes: %w", err))
	} else if conflict {
		return t.startFailureLocked(fmt.Errorf("%w: %s", ErrRouteConflict, route))
	}
	address, err := addOverlayAddress(t.luid, t.localIP)
	if err != nil {
		return t.startFailureLocked(err)
	}
	t.address = &address
	if err := setOverlayMTU(t.luid, t.mtu); err != nil {
		return t.startFailureLocked(err)
	}
	var bind conn.Bind
	if t.native {
		t.direct = &stunBind{Bind: conn.NewDefaultBind(), interfaces: t.interfaces}
		if t.masked {
			t.direct.mask = newUDPMask()
		}
		bind = t.direct
	} else {
		t.bind = icebind.New()
		bind = t.bind
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	t.device = device.NewDevice(&policyTUN{Device: adapter, policy: t.policy}, bind, logger)
	config := "private_key=" + hex.EncodeToString(t.privateKey[:]) + "\n"
	if t.native {
		config += fmt.Sprintf("listen_port=%d\n", t.port)
	}
	if err := t.device.IpcSet(config); err != nil {
		return t.startFailureLocked(fmt.Errorf("configure WireGuard identity: %w", err))
	}
	if err := t.device.Up(); err != nil {
		return t.startFailureLocked(fmt.Errorf("start WireGuard: %w", err))
	}
	t.running = true
	for _, p := range t.peers {
		if err := t.installPeerLocked(p); err != nil {
			return t.startFailureLocked(fmt.Errorf("install peer %s: %w", p.id, err))
		}
	}
	var echo *net.UDPConn
	for attempt := 0; attempt < 30; attempt++ {
		echo, err = net.ListenUDP("udp4", &net.UDPAddr{IP: t.localIP, Port: ProbePort})
		if err == nil || !errors.Is(err, windows.WSAEADDRNOTAVAIL) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return t.startFailureLocked(fmt.Errorf("bind overlay probe endpoint: %w", err))
	}
	t.echo = echo
	t.echoDone = make(chan struct{})
	go serveEcho(echo, t.echoDone, func(ip net.IP) bool { _, ok := t.echoPeers.Load(ip.String()); return ok })
	return nil
}

// Stop removes only entries created by this Tunnel, closes the owned ICE
// connections and removes the Wintun adapter. It is idempotent.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopLocked()
}

// RemovePeer revokes a WireGuard key before removing its route and ICE path.
func (t *Tunnel) RemovePeer(peerID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peers[peerID]
	if p == nil {
		return ErrUnknownPeer
	}
	if t.running {
		if err := t.device.IpcSet("public_key=" + hex.EncodeToString(p.publicKey[:]) + "\nremove=true\n"); err != nil {
			return errors.Join(fmt.Errorf("revoke peer: %w", err), t.stopLocked())
		}
	}
	if err := removePeerRoute(p.route); err != nil {
		return errors.Join(fmt.Errorf("remove revoked peer route: %w", err), t.stopLocked())
	}
	p.route = nil
	delete(t.peers, peerID)
	if t.direct != nil && t.direct.mask != nil {
		t.direct.mask.remove(peerID)
	}
	t.echoPeers.Delete(p.ip.String())
	t.policy.setPeer(p.ip, false)
	if t.bind != nil && p.attached {
		t.bind.Detach(peerID)
	} else if p.conn != nil {
		_ = p.conn.Close()
	}
	return nil
}

func (t *Tunnel) Stats(peerID string) (PeerStats, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peers[peerID]
	if p == nil {
		return PeerStats{}, ErrUnknownPeer
	}
	if !t.running || t.device == nil {
		return PeerStats{}, ErrNotStarted
	}
	raw, err := t.device.IpcGet()
	if err != nil {
		return PeerStats{}, err
	}
	stats, err := parsePeerStats(raw, hex.EncodeToString(p.publicKey[:]))
	if err != nil {
		return PeerStats{}, err
	}
	stats.PeerID = peerID
	stats.VirtualIP = p.ip.String()
	return stats, nil
}

// Probe confirms a bidirectional application datagram over the virtual IP
// and a recent WireGuard handshake. ICE pair and physical egress classification
// must be checked separately before reporting Direct.
func (t *Tunnel) Probe(peerID string) (ProbeResult, error) {
	t.mu.Lock()
	p := t.peers[peerID]
	if p == nil {
		t.mu.Unlock()
		return ProbeResult{}, ErrUnknownPeer
	}
	if !t.running {
		t.mu.Unlock()
		return ProbeResult{}, ErrNotStarted
	}
	peerIP := append(net.IP(nil), p.ip...)
	localIP := append(net.IP(nil), t.localIP...)
	t.mu.Unlock()
	before, err := t.Stats(peerID)
	if err != nil {
		return ProbeResult{}, err
	}

	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: localIP}, &net.UDPAddr{IP: peerIP, Port: ProbePort})
	if err != nil {
		return ProbeResult{}, fmt.Errorf("open overlay probe: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeWait)); err != nil {
		return ProbeResult{}, err
	}
	request := make([]byte, len(probePrefix)+32)
	copy(request, probePrefix)
	if _, err := rand.Read(request[len(probePrefix):]); err != nil {
		return ProbeResult{}, err
	}
	started := time.Now()
	if _, err := conn.Write(request); err != nil {
		return ProbeResult{}, fmt.Errorf("send overlay probe: %w", err)
	}
	buf := make([]byte, len(request)+1)
	n, err := conn.Read(buf)
	if err != nil || n != len(request) || !bytes.Equal(buf[:n], request) {
		return ProbeResult{}, errors.Join(ErrProbeFailed, err)
	}
	rtt := time.Since(started)
	stats, err := t.Stats(peerID)
	if err != nil {
		return ProbeResult{}, err
	}
	if stats.LastHandshake.IsZero() || time.Since(stats.LastHandshake) > 3*time.Minute ||
		stats.TxBytes <= before.TxBytes || stats.RxBytes <= before.RxBytes {
		return ProbeResult{}, ErrProbeFailed
	}
	return ProbeResult{PeerID: peerID, RTT: rtt, LastHandshake: stats.LastHandshake, TxBytes: stats.TxBytes, RxBytes: stats.RxBytes}, nil
}

func (t *Tunnel) installPeerLocked(p *peer) (result error) {
	if conflict, route, err := platform.RouteConflict(t.groupCIDR, t.ifIndex); err != nil {
		return fmt.Errorf("inspect overlay routes: %w", err)
	} else if conflict {
		return fmt.Errorf("%w: %s", ErrRouteConflict, route)
	}
	row, err := addPeerRoute(t.luid, p.ip)
	if err != nil {
		return fmt.Errorf("add peer /32 route: %w", err)
	}
	p.route = &row
	var mask *udpMask
	if t.direct != nil {
		mask = t.direct.mask
	}
	defer func() {
		if result == nil {
			return
		}
		revokeErr := t.device.IpcSet("public_key=" + hex.EncodeToString(p.publicKey[:]) + "\nremove=true\n")
		if p.attached {
			t.bind.Detach(p.id)
			p.attached = false
		}
		if mask != nil {
			mask.remove(p.id)
		}
		result = errors.Join(result, revokeErr, removePeerRoute(p.route))
		p.route = nil
		if revokeErr != nil {
			result = errors.Join(result, t.stopLocked())
		}
	}()
	if mask != nil {
		if p.crypto == nil {
			return errors.New("missing masking keys for secure peer")
		}
		if err := mask.add(p.id, p.crypto); err != nil {
			return err
		}
	}
	endpoint := ""
	if t.native {
		if p.endpoint.IsValid() {
			endpoint = "endpoint=" + directEndpoint(p.id, p.endpoint.String(), t.masked) + "\n"
		}
	} else {
		if err := t.bind.Attach(p.id, p.conn); err != nil {
			return fmt.Errorf("attach ICE transport: %w", err)
		}
		p.attached = true
		endpoint = "endpoint=" + p.id + "\n"
	}
	config := "public_key=" + hex.EncodeToString(p.publicKey[:]) + "\n" +
		endpoint +
		"allowed_ip=" + p.ip.String() + "/32\n" +
		"persistent_keepalive_interval=25\n"
	if p.crypto != nil {
		config += "preshared_key=" + hex.EncodeToString(p.crypto.preshared[:]) + "\n"
	}
	if err := t.device.IpcSet(config); err != nil {
		return fmt.Errorf("configure WireGuard peer: %w", err)
	}
	if conflict, route, err := platform.RouteConflict(t.groupCIDR, t.ifIndex); err != nil || conflict {
		if err != nil {
			return fmt.Errorf("verify overlay routes: %w", err)
		}
		return fmt.Errorf("%w: %s", ErrRouteConflict, route)
	}
	return nil
}

func (t *Tunnel) startFailureLocked(err error) error {
	return errors.Join(err, t.stopLocked())
}

func (t *Tunnel) stopLocked() error {
	if t.stopped {
		return nil
	}
	t.stopped = true
	t.running = false
	if t.echo != nil {
		_ = t.echo.Close()
		<-t.echoDone
		t.echo = nil
	}
	if t.device != nil {
		_ = t.device.Down()
	}
	var errs []error
	for _, p := range t.peers {
		if err := removePeerRoute(p.route); err != nil {
			errs = append(errs, err)
		}
		p.route = nil
		if !p.attached && p.conn != nil {
			_ = p.conn.Close()
		}
		p.attached = false
	}
	if err := removeOverlayAddress(t.address); err != nil {
		errs = append(errs, err)
	}
	t.address = nil
	if t.device != nil {
		t.device.Close() // closes Bind and Wintun device
		t.device = nil
		t.adapter = nil
	} else {
		if t.bind != nil {
			if err := t.bind.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if t.adapter != nil {
			if err := t.adapter.Close(); err != nil {
				errs = append(errs, err)
			}
			t.adapter = nil
		}
	}
	t.bind = nil
	t.direct = nil
	return errors.Join(errs...)
}

func serveEcho(conn *net.UDPConn, done chan<- struct{}, allowed func(net.IP) bool) {
	defer close(done)
	buf := make([]byte, len(probePrefix)+33)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == len(probePrefix)+32 && allowed(remote.IP) && bytes.Equal(buf[:len(probePrefix)], []byte(probePrefix)) {
			_, _ = conn.WriteToUDP(buf[:n], remote) // same-size reply, no amplification
		}
	}
}

func parsePeerStats(raw, keyHex string) (PeerStats, error) {
	var stats PeerStats
	current, found := false, false
	for scanner := bufio.NewScanner(strings.NewReader(raw)); scanner.Scan(); {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			current = strings.EqualFold(value, keyHex)
			found = found || current
			continue
		}
		if !current {
			continue
		}
		switch key {
		case "endpoint":
			stats.Endpoint = value
		case "last_handshake_time_sec":
			sec, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return PeerStats{}, err
			}
			if sec > 0 {
				stats.LastHandshake = time.Unix(sec, 0)
			}
		case "tx_bytes":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return PeerStats{}, err
			}
			stats.TxBytes = v
		case "rx_bytes":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return PeerStats{}, err
			}
			stats.RxBytes = v
		}
	}
	if !found {
		return PeerStats{}, ErrUnknownPeer
	}
	return stats, nil
}

func unusableHost(ip net.IP, network *net.IPNet) bool {
	base := network.IP.To4()
	if base == nil || ip.Equal(base) {
		return true
	}
	broadcast := make(net.IP, 4)
	for i := range 4 {
		broadcast[i] = base[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}

func validPeerID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func newAdapterName() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return "DirectLAN-" + hex.EncodeToString(suffix[:]), nil
}
