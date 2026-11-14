//go:build windows

package mesh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"directlan/internal/identity"
	"directlan/internal/localipc"
	"directlan/internal/tunnel"
)

// This harness executes real signed-code, service admission, reassembly and
// acknowledgement handlers. Only the OS adapter/UDP boundary is substituted;
// real UDP/AEAD/WireGuard packet paths have separate tunnel integration tests.
type exchangePeer struct {
	key      []byte
	ip       netip.Addr
	endpoint netip.AddrPort
}
type exchangeTunnel struct {
	bus                *exchangeBus
	node               *node
	endpoint           netip.AddrPort
	localIP            netip.Addr
	data, control      map[string]*exchangePeer
	stops, readdresses int
}
type exchangeEnvelope struct {
	from, to *exchangeTunnel
	payload  []byte
}
type exchangeBus struct {
	t               *testing.T
	nodes           map[netip.AddrPort]*exchangeTunnel
	queue           []exchangeEnvelope
	drop            func(exchangeEnvelope) bool
	reverse         bool
	duplicateRoster bool
}

func (w *exchangeTunnel) AddSecureDirectPeer(id string, key []byte, ip net.IP, ep netip.AddrPort) error {
	if w.data[id] != nil {
		return errors.New("duplicate peer")
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok || a.Unmap() == w.localIP {
		return errors.New("invalid peer IP")
	}
	for _, p := range w.data {
		if p.ip == a.Unmap() || bytes.Equal(p.key, key) {
			return errors.New("duplicate address/key")
		}
	}
	w.data[id] = &exchangePeer{append([]byte(nil), key...), a.Unmap(), ep}
	return nil
}
func (w *exchangeTunnel) ConfigureControlPeer(id string, key []byte, ep netip.AddrPort) error {
	w.control[id] = &exchangePeer{key: append([]byte(nil), key...), endpoint: ep}
	return nil
}
func (w *exchangeTunnel) RemovePeer(id string) error {
	if w.data[id] == nil {
		return tunnel.ErrUnknownPeer
	}
	delete(w.data, id)
	delete(w.control, id)
	return nil
}
func (w *exchangeTunnel) ReaddressPending(ip net.IP) error {
	if len(w.data) != 0 {
		return errors.New("admitted transport cannot be renumbered")
	}
	w.localIP, _ = netip.AddrFromSlice(ip)
	w.localIP = w.localIP.Unmap()
	w.readdresses++
	return nil
}
func (w *exchangeTunnel) Stop() error                 { w.stops++; return nil }
func (w *exchangeTunnel) DirectPort() (uint16, error) { return w.endpoint.Port(), nil }
func (w *exchangeTunnel) DiscoverDirectEndpoint(context.Context, netip.AddrPort) (netip.AddrPort, error) {
	return w.endpoint, nil
}
func (w *exchangeTunnel) SetDirectEndpoint(id string, ep netip.AddrPort) error {
	if w.data[id] == nil {
		return tunnel.ErrUnknownPeer
	}
	w.data[id].endpoint = ep
	return nil
}
func (w *exchangeTunnel) SendControl(id string, payload []byte) error {
	p := w.control[id]
	if p == nil {
		return tunnel.ErrUnknownPeer
	}
	dest := w.bus.nodes[p.endpoint]
	if dest == nil {
		return nil
	} // UDP loss or stale mapping
	key, _ := dest.node.keys.WireGuardPublic()
	if memberID(Member{Identity: dest.node.keys.IdentityPublic()}) != id || !bytes.Equal(key, p.key) {
		return nil
	}
	w.bus.queue = append(w.bus.queue, exchangeEnvelope{w, dest, append([]byte(nil), payload...)})
	if w.bus.duplicateRoster && len(payload) > 16 && payload[16] == controlRosterKind {
		w.bus.queue = append(w.bus.queue, exchangeEnvelope{w, dest, append([]byte(nil), payload...)})
	}
	return nil
}
func (w *exchangeTunnel) ControlMessages() <-chan tunnel.ControlMessage { return nil }
func (w *exchangeTunnel) Stats(string) (tunnel.PeerStats, error)        { return tunnel.PeerStats{}, nil }
func (w *exchangeTunnel) Probe(string) (tunnel.ProbeResult, error)      { return tunnel.ProbeResult{}, nil }
func (w *exchangeTunnel) Diagnostics(string) (tunnel.PeerDiagnostics, error) {
	return tunnel.PeerDiagnostics{}, nil
}
func (w *exchangeTunnel) TransportDiagnostics(string) (tunnel.TransportDiagnostics, error) {
	return tunnel.TransportDiagnostics{}, nil
}

func (b *exchangeBus) pump() {
	b.t.Helper()
	for limit := 0; len(b.queue) != 0; limit++ {
		if limit > 2000 {
			b.t.Fatal("control exchange did not quiesce")
		}
		index := 0
		if b.reverse {
			index = len(b.queue) - 1
		}
		e := b.queue[index]
		b.queue = append(b.queue[:index], b.queue[index+1:]...)
		if b.drop != nil && b.drop(e) {
			continue
		}
		id := memberID(Member{Identity: e.from.node.keys.IdentityPublic()})
		p := e.to.control[id]
		key, _ := e.from.node.keys.WireGuardPublic()
		if p == nil || !bytes.Equal(key, p.key) {
			continue
		}
		e.to.node.handleControl(e.to, tunnel.ControlMessage{PeerID: id, Endpoint: e.from.endpoint, Payload: e.payload})
	}
}
func newExchangeNode(t *testing.T, bus *exchangeBus, index int, invite *node) *node {
	t.Helper()
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ep := netip.MustParseAddrPort(fmt.Sprintf("9.9.9.%d:%d", index+1, 51000+index))
	n := &node{keys: keys, path: filepath.Join(t.TempDir(), "mesh.json"), wake: make(chan struct{}, 1), controlWake: make(chan struct{}, 1), members: make(map[string]memberStatus), scanned: true, endpoints: []netip.AddrPort{ep}}
	if invite == nil {
		key, _ := keys.WireGuardPublic()
		code := Code{Kind: "network", Session: "00112233445566778899aabbccddeeff", Network: netip.MustParsePrefix("10.199.72.0/24"), Owner: keys.IdentityPublic(), Revision: 1, Masked: true}
		code.Members = []Member{{Identity: keys.IdentityPublic(), WireGuard: key, Name: "Owner", IP: code.Network.Addr().Next(), Endpoints: []netip.AddrPort{ep}}}
		n.roster, n.p.Code, err = n.sign(code)
		n.p.Name, n.p.LocalIP = "Owner", code.Members[0].IP
	} else {
		n.roster, err = Decode(invite.p.Code, time.Now())
		n.p.Code, n.p.Name, n.p.Pending = invite.p.Code, fmt.Sprintf("Guest%d", index), true
		n.p.LocalIP, _ = freeAddress(n.roster)
	}
	if err != nil {
		t.Fatal(err)
	}
	w := &exchangeTunnel{bus: bus, node: n, endpoint: ep, localIP: n.p.LocalIP, data: make(map[string]*exchangePeer), control: make(map[string]*exchangePeer)}
	n.wg, n.p.Port = w, ep.Port()
	bus.nodes[ep] = w
	var nonce [16]byte
	var secret [32]byte
	_, _ = rand.Read(nonce[:])
	_, _ = rand.Read(secret[:])
	n.resetControl(nonce, secret)
	if invite != nil {
		owner := n.roster.Members[0]
		_ = w.ConfigureControlPeer(memberID(owner), owner.WireGuard, owner.Endpoints[0])
	}
	if err = n.save(n.p); err != nil {
		t.Fatal(err)
	}
	return n
}
func approveExchangeGuest(t *testing.T, owner, guest *node) {
	t.Helper()
	result, apiErr := guest.handle(context.Background(), localipc.Request{Method: "mesh.code"})
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	args, _ := json.Marshal(map[string]string{"code": result.(map[string]string)["code"]})
	if _, apiErr = owner.handle(context.Background(), localipc.Request{Method: "mesh.accept", Params: args}); apiErr != nil {
		t.Fatal(apiErr)
	}
}
func assertExchangeConverged(t *testing.T, owner *node, nodes ...*node) {
	t.Helper()
	for _, n := range nodes {
		w := n.wg.(*exchangeTunnel)
		if n.p.Pending || n.roster.Revision != owner.roster.Revision || n.p.Code != owner.p.Code || len(w.data) != len(owner.roster.Members)-1 || w.stops != 0 {
			t.Fatalf("node %s did not converge: revision=%d want=%d pending=%t peers=%d stops=%d", n.p.Name, n.roster.Revision, owner.roster.Revision, n.p.Pending, len(w.data), w.stops)
		}
		for _, member := range owner.roster.Members {
			if bytes.Equal(member.Identity, n.keys.IdentityPublic()) {
				continue
			}
			peer := w.data[memberID(member)]
			if peer == nil || peer.ip != member.IP || !bytes.Equal(peer.key, member.WireGuard) {
				t.Fatalf("%s missing direct authorization to %s", n.p.Name, member.Name)
			}
		}
	}
}

func rosterFragment(e exchangeEnvelope) bool {
	return len(e.payload) > 16+rosterHeaderSize && e.payload[16] == controlRosterKind
}
func helloRevision(e exchangeEnvelope) uint64 {
	_, _, revision, ok := parseAdmissionHello(e.payload)
	if !ok {
		return ^uint64(0)
	}
	return revision
}
func pushExchangeRoster(owner *node) {
	for id := range owner.controlGuests {
		owner.lastTransfer[id] = time.Now().Add(-3 * time.Second)
	}
	owner.driveOwnerControl()
}

func TestFourNodeServiceDistributesRosterWithoutGuestCodeExchange(t *testing.T) {
	b := &exchangeBus{t: t, nodes: make(map[netip.AddrPort]*exchangeTunnel)}
	o := newExchangeNode(t, b, 0, nil)
	a := newExchangeNode(t, b, 1, o)
	approveExchangeGuest(t, o, a)
	a.sendHello()
	b.pump()
	assertExchangeConverged(t, o, o, a)
	oldRuntime, oldPeer, oldPort := a.wg, a.wg.(*exchangeTunnel).data[memberID(o.roster.Members[0])], a.p.Port
	// B and C start from the same invitation and initially choose the same IP.
	c := newExchangeNode(t, b, 2, o)
	d := newExchangeNode(t, b, 3, o)
	if c.p.LocalIP != d.p.LocalIP {
		t.Fatal("fixture did not reproduce concurrent provisional address collision")
	}
	approveExchangeGuest(t, o, c)
	// Existing A does not send another HELLO: the owner must push the change.
	pushExchangeRoster(o)
	c.sendHello()
	b.pump()
	assertExchangeConverged(t, o, o, a, c)
	approveExchangeGuest(t, o, d)
	droppedPart, droppedACK := false, false
	b.drop = func(e exchangeEnvelope) bool {
		if e.to.node == a && rosterFragment(e) && binary.BigEndian.Uint16(e.payload[16+41:16+43]) == 1 && !droppedPart {
			droppedPart = true
			return true
		}
		if e.from.node == c && helloRevision(e) == o.roster.Revision && !droppedACK {
			droppedACK = true
			return true
		}
		return false
	}
	pushExchangeRoster(o)
	d.sendHello()
	b.pump()
	if !droppedPart || a.roster.Revision == o.roster.Revision {
		t.Fatal("incomplete roster was applied or loss was not exercised")
	}
	// Retry without application probes, manual codes, guest polls or sleeps.
	b.drop = nil
	b.reverse, b.duplicateRoster = true, true
	for range 3 {
		pushExchangeRoster(o)
		b.pump()
	}
	assertExchangeConverged(t, o, o, a, c, d)
	if !droppedACK {
		t.Fatal("lost acknowledgement was not exercised")
	}
	if a.wg != oldRuntime || a.p.Port != oldPort || a.wg.(*exchangeTunnel).data[memberID(o.roster.Members[0])] != oldPeer {
		t.Fatal("adding a third/fourth member reset an existing connection")
	}
	if d.wg.(*exchangeTunnel).readdresses != 1 || d.p.LocalIP == c.p.LocalIP {
		t.Fatal("owner's distinct address was not installed in place")
	}
	for _, n := range []*node{a, c, d} {
		if o.confirmed[memberID(Member{Identity: n.keys.IdentityPublic()})] != o.roster.Revision {
			t.Fatal("owner missed automatic roster acknowledgement")
		}
	}
	// A's public address changes. Its authenticated return path must be
	// republished for C and D automatically, without copying a fresh request.
	aw := a.wg.(*exchangeTunnel)
	delete(b.nodes, aw.endpoint)
	aw.endpoint = netip.MustParseAddrPort("9.9.9.90:53090")
	b.nodes[aw.endpoint] = aw
	a.endpoints = []netip.AddrPort{aw.endpoint}
	a.lastControlHello = time.Time{}
	for id := range o.lastTransfer {
		o.lastTransfer[id] = time.Now().Add(-3 * time.Second)
	}
	a.sendHello()
	b.pump()
	for range 3 {
		pushExchangeRoster(o)
		b.pump()
	}
	assertExchangeConverged(t, o, o, a, c, d)
	aid := memberID(Member{Identity: a.keys.IdentityPublic()})
	for _, n := range []*node{c, d} {
		if n.wg.(*exchangeTunnel).data[aid].endpoint != aw.endpoint {
			t.Fatal("guest address change was not distributed to other guests")
		}
	}
	// Removing D also preserves the other guest links and revokes its key on
	// every remaining node after receipt of the new signed roster.
	did := memberID(Member{Identity: d.keys.IdentityPublic()})
	args, _ := json.Marshal(map[string]string{"id": did})
	if _, apiErr := o.handle(context.Background(), localipc.Request{Method: "mesh.remove", Params: args}); apiErr != nil {
		t.Fatal(apiErr)
	}
	pushExchangeRoster(o)
	b.pump()
	assertExchangeConverged(t, o, o, a, c)
	for _, n := range []*node{o, a, c} {
		if n.wg.(*exchangeTunnel).data[did] != nil {
			t.Fatal("removed member retained a data authorization")
		}
	}
}

func TestSignedRevocationSaveFailureStopsGuestWithoutRestoringRevokedPeer(t *testing.T) {
	b := &exchangeBus{t: t, nodes: make(map[netip.AddrPort]*exchangeTunnel)}
	o := newExchangeNode(t, b, 0, nil)
	a := newExchangeNode(t, b, 1, o)
	approveExchangeGuest(t, o, a)
	a.sendHello()
	b.pump()
	c := newExchangeNode(t, b, 2, o)
	approveExchangeGuest(t, o, c)
	pushExchangeRoster(o)
	c.sendHello()
	b.pump()
	assertExchangeConverged(t, o, o, a, c)
	wire := a.wg.(*exchangeTunnel)
	id := memberID(Member{Identity: c.keys.IdentityPublic()})
	args, _ := json.Marshal(map[string]string{"id": id})
	if _, apiErr := o.handle(context.Background(), localipc.Request{Method: "mesh.remove", Params: args}); apiErr != nil {
		t.Fatal(apiErr)
	}
	// An existing directory cannot be replaced by the saved profile file.
	a.path = t.TempDir()
	if err := a.applyControlRoster(o.p.Code, o.roster.Revision); err == nil {
		t.Fatal("profile save unexpectedly succeeded")
	}
	if a.wg != nil || wire.stops != 1 || wire.data[id] != nil {
		t.Fatal("failed signed revocation kept a live runtime or restored its revoked key")
	}
}
