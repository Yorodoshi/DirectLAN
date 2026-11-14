//go:build windows

package mesh

import (
	"bytes"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"directlan/internal/tunnel"
)

type pushTestPacket struct {
	id       string
	endpoint netip.AddrPort
	payload  []byte
}
type pushTestTunnel struct {
	meshTunnel
	keys      map[string][]byte
	endpoints map[string]netip.AddrPort
	packets   []pushTestPacket
}

func (wire *pushTestTunnel) ConfigureControlPeer(id string, key []byte, endpoint netip.AddrPort) error {
	if !bytes.Equal(wire.keys[id], key) {
		return errors.New("unexpected control public key")
	}
	wire.endpoints[id] = endpoint
	return nil
}
func (wire *pushTestTunnel) SetDirectEndpoint(string, netip.AddrPort) error { return nil }
func (wire *pushTestTunnel) SendControl(id string, payload []byte) error {
	wire.packets = append(wire.packets, pushTestPacket{id: id, endpoint: wire.endpoints[id], payload: append([]byte(nil), payload...)})
	return nil
}

func pushOwnerFixture(t *testing.T) (*node, *pushTestTunnel, Member) {
	t.Helper()
	keys, code, text := lifecycleNetwork(t)
	wire := &pushTestTunnel{keys: make(map[string][]byte), endpoints: make(map[string]netip.AddrPort)}
	for _, member := range code.Members[1:] {
		wire.keys[memberID(member)] = member.WireGuard
	}
	n := &node{keys: keys, roster: code, wg: wire, path: filepath.Join(t.TempDir(), "owner.mesh.json"),
		p: profile{Code: text, LocalIP: code.Members[0].IP}, scanned: true, endpoints: append([]netip.AddrPort(nil), code.Members[0].Endpoints...),
		wake: make(chan struct{}, 1), controlWake: make(chan struct{}, 1)}
	n.resetControl([16]byte{1}, [32]byte{2})
	if err := n.save(n.p); err != nil {
		t.Fatal(err)
	}
	return n, wire, code.Members[1]
}

func pushValidHello(t *testing.T, n *node, member Member, nonce [16]byte, endpoint netip.AddrPort, revision uint64) {
	t.Helper()
	cookie := admissionCookie(n.cookieSecret, memberID(member), endpoint, nonce)
	n.handleControl(n.wg, tunnel.ControlMessage{PeerID: memberID(member), Endpoint: endpoint, Payload: admissionHello(nonce, cookie, revision)})
}

func pushBumpRoster(t *testing.T, n *node) {
	t.Helper()
	code := n.roster
	code.Revision++
	code, text, err := n.sign(code)
	if err != nil {
		t.Fatal(err)
	}
	n.roster, n.p.Code = code, text
	if err := n.save(n.p); err != nil {
		t.Fatal(err)
	}
}

func pushRosterPackets(packets []pushTestPacket) []pushTestPacket {
	var found []pushTestPacket
	for _, packet := range packets {
		if len(packet.payload) > 16 && packet.payload[16] == controlRosterKind {
			found = append(found, packet)
		}
	}
	return found
}

func TestOwnerPushRetriesWithoutAnotherGuestPullAndStopsAfterAcknowledgement(t *testing.T) {
	n, wire, member := pushOwnerFixture(t)
	id, endpoint, nonce := memberID(member), member.Endpoints[0], [16]byte{7}
	pushValidHello(t, n, member, nonce, endpoint, n.roster.Revision)
	wire.packets = nil
	pushBumpRoster(t, n)
	now := time.Now()
	n.driveOwnerControlAt(now)
	packets := pushRosterPackets(wire.packets)
	if len(packets) == 0 {
		t.Fatal("owner did not push the new revision without another guest hello")
	}
	var assembly rosterAssembly
	var text string
	for _, packet := range packets {
		if packet.id != id || packet.endpoint != endpoint || !bytes.Equal(packet.payload[:16], nonce[:]) {
			t.Fatal("push used an unproven return path or wrong recipient generation")
		}
		complete, revision, err := assembly.add(packet.payload[16:], now)
		if err != nil {
			t.Fatal(err)
		}
		if complete != "" {
			text = complete
			if revision != n.roster.Revision {
				t.Fatal("push header revision differs")
			}
		}
	}
	if text != n.p.Code {
		t.Fatal("push did not preserve the complete owner-signed roster")
	}
	if _, err := Decode(text, time.Now()); err != nil {
		t.Fatal(err)
	}
	wire.packets = nil
	n.driveOwnerControlAt(now.Add(1900 * time.Millisecond))
	if len(wire.packets) != 0 {
		t.Fatal("owner push ignored its per-peer backoff")
	}
	n.driveOwnerControlAt(now.Add(2 * time.Second))
	if len(pushRosterPackets(wire.packets)) == 0 {
		t.Fatal("lost roster or acknowledgement was not retried")
	}
	pushValidHello(t, n, member, nonce, endpoint, n.roster.Revision)
	wire.packets = nil
	n.driveOwnerControlAt(now.Add(4 * time.Second))
	if len(wire.packets) != 0 {
		t.Fatal("owner kept pushing a revision the guest acknowledged")
	}
}

func TestOwnerNeverPushesToUnvalidatedNonceOrSource(t *testing.T) {
	for _, change := range []string{"no cookie", "different source", "different nonce"} {
		t.Run(change, func(t *testing.T) {
			n, wire, member := pushOwnerFixture(t)
			id, original, nonce := memberID(member), member.Endpoints[0], [16]byte{7}
			cookie := admissionCookie(n.cookieSecret, id, original, nonce)
			endpoint := original
			switch change {
			case "no cookie":
				cookie = [16]byte{}
			case "different source":
				endpoint = netip.MustParseAddrPort("9.9.9.9:55001")
			case "different nonce":
				nonce[0]++
			}
			n.handleControl(n.wg, tunnel.ControlMessage{PeerID: id, Endpoint: endpoint, Payload: admissionHello(nonce, cookie, n.roster.Revision)})
			if len(n.controlGuests) != 0 || len(pushRosterPackets(wire.packets)) != 0 {
				t.Fatal("unvalidated return path received an admission transfer")
			}
			pushBumpRoster(t, n)
			wire.packets = nil
			n.driveOwnerControlAt(time.Now())
			if len(wire.packets) != 0 {
				t.Fatal("owner retried a roster to a source that never proved its cookie")
			}
		})
	}
}

func TestInvalidHelloCannotRedirectAnAlreadyProvenPush(t *testing.T) {
	n, wire, member := pushOwnerFixture(t)
	id, endpoint, nonce := memberID(member), member.Endpoints[0], [16]byte{7}
	pushValidHello(t, n, member, nonce, endpoint, n.roster.Revision)
	pushBumpRoster(t, n)
	spoofed := netip.MustParseAddrPort("9.9.9.9:55001")
	otherNonce := nonce
	otherNonce[0]++
	oldCookie := admissionCookie(n.cookieSecret, id, endpoint, nonce)
	n.handleControl(n.wg, tunnel.ControlMessage{PeerID: id, Endpoint: spoofed, Payload: admissionHello(otherNonce, oldCookie, n.roster.Revision-1)})
	if guest := n.controlGuests[id]; guest.endpoint != endpoint || guest.nonce != nonce {
		t.Fatal("invalid hello replaced an existing return-path proof")
	}
	wire.packets = nil
	n.driveOwnerControlAt(time.Now())
	packets := pushRosterPackets(wire.packets)
	if len(packets) == 0 {
		t.Fatal("an invalid hello suppressed the legitimate owner's push")
	}
	for _, packet := range packets {
		if packet.endpoint != endpoint || !bytes.Equal(packet.payload[:16], nonce[:]) {
			t.Fatal("large transfer followed the unproven challenge destination")
		}
	}
}

func TestOwnerPushRejectsExpiredRemovedAndChangedKeys(t *testing.T) {
	for _, change := range []string{"expired", "removed", "key changed"} {
		t.Run(change, func(t *testing.T) {
			n, wire, member := pushOwnerFixture(t)
			id := memberID(member)
			pushValidHello(t, n, member, [16]byte{7}, member.Endpoints[0], n.roster.Revision)
			now := time.Now()
			switch change {
			case "expired":
				guest := n.controlGuests[id]
				guest.validated = now.Add(-authenticatedEndpointTTL)
				n.controlGuests[id] = guest
			case "removed":
				n.roster.Members = append(append([]Member(nil), n.roster.Members[:1]...), n.roster.Members[2:]...)
			case "key changed":
				replacement, _ := testMember(t, "replacement", "10.213.47.2")
				n.roster.Members[1].WireGuard = replacement.WireGuard
			}
			pushBumpRoster(t, n)
			wire.packets = nil
			n.driveOwnerControlAt(now)
			if len(wire.packets) != 0 {
				t.Fatal("stale source proof or removed control key received a push")
			}
			if change != "expired" {
				if _, ok := n.controlGuests[id]; ok {
					t.Fatal("cache kept a member/key absent from the current signed roster")
				}
			}
		})
	}
}

func TestPublishedGuestEndpointIsFirstBoundedAndStable(t *testing.T) {
	n, _, member := pushOwnerFixture(t)
	id := memberID(member)
	previous := member.Endpoints[0]
	member.Endpoints = []netip.AddrPort{previous, netip.MustParseAddrPort("8.8.4.4:50002"), netip.MustParseAddrPort("1.1.1.1:50002"), netip.MustParseAddrPort("1.0.0.1:50002")}
	n.roster.Members[1] = member
	pushBumpRoster(t, n)
	before := n.roster.Revision
	fresh := netip.MustParseAddrPort("9.9.9.9:55001")
	if err := n.publishGuestEndpoint(id, fresh, previous); err != nil {
		t.Fatal(err)
	}
	updated := n.roster.Members[1].Endpoints
	if len(updated) != 4 || updated[0] != fresh || n.roster.Revision != before+1 {
		t.Fatal("fresh observed candidate was not prioritized within the signed endpoint bound")
	}
	for _, old := range member.Endpoints[1:] {
		if !slices.Contains(updated, old) {
			t.Fatalf("alternate signed candidate disappeared: %s", old)
		}
	}
	text := n.p.Code
	if _, err := Decode(text, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := n.publishGuestEndpoint(id, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	if err := n.publishGuestEndpoint(id, member.Endpoints[1], fresh); err != nil {
		t.Fatal(err)
	}
	if n.roster.Revision != before+1 || n.p.Code != text {
		t.Fatal("repeated/alternate known candidates caused a signed revision ping-pong")
	}
}
