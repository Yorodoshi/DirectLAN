//go:build windows

package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Native UDP binds exercise the real receive demultiplexer without requiring a
// Wintun driver, administrator rights, or modifications to the host network.
func controlTestTunnel(t *testing.T, private *ecdh.PrivateKey, masked bool) (*Tunnel, netip.AddrPort) {
	t.Helper()
	control := newControlTransport()
	bind := &stunBind{Bind: conn.NewDefaultBind(), control: control}
	if masked {
		bind.mask = newUDPMask()
	}
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	node := &Tunnel{running: true, native: true, secureContext: "control-test", direct: bind, control: control}
	copy(node.privateKey[:], private.Bytes())
	done := make(chan struct{}, len(receivers))
	for _, receive := range receivers {
		go func() {
			defer func() { done <- struct{}{} }()
			packets := make([][]byte, bind.BatchSize())
			for i := range packets {
				packets[i] = make([]byte, 1500)
			}
			sizes, endpoints := make([]int, len(packets)), make([]conn.Endpoint, len(packets))
			for {
				if _, err := receive(packets, sizes, endpoints); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		node.mu.Lock()
		node.running = false
		node.mu.Unlock()
		_ = bind.Close()
		for range receivers {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("control receiver did not stop when the UDP bind closed")
			}
		}
	})
	return node, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func expectControlMessage(t *testing.T, node *Tunnel, id string, payload []byte, source netip.AddrPort) ControlMessage {
	t.Helper()
	select {
	case got := <-node.ControlMessages():
		if got.PeerID != id || !bytes.Equal(got.Payload, payload) || got.Endpoint != source {
			t.Fatalf("control message = %+v, want peer %s payload %q source %s", got, id, payload, source)
		}
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("control message was not delivered")
	}
	return ControlMessage{}
}

func TestControlSharesWireGuardSocketAndRequiresExplicitEndpointApproval(t *testing.T) {
	for _, masked := range []bool{false, true} {
		name := "plain"
		if masked {
			name = "masked"
		}
		t.Run(name, func(t *testing.T) {
			aKey, bKey, _, _ := cryptoPair(t, "control-test")
			a, aAddress := controlTestTunnel(t, aKey, masked)
			b, bAddress := controlTestTunnel(t, bKey, masked)
			if err := a.ConfigureControlPeer("b", bKey.PublicKey().Bytes(), bAddress); err != nil {
				t.Fatal(err)
			}
			if err := b.ConfigureControlPeer("a", aKey.PublicKey().Bytes(), netip.AddrPort{}); err != nil {
				t.Fatal(err)
			}
			if err := b.SendControl("a", []byte("no known address yet")); err == nil {
				t.Fatal("sending before endpoint discovery succeeded")
			}
			payload := bytes.Repeat([]byte{0x6a}, ControlPayloadLimit)
			if err := a.SendControl("b", payload); err != nil {
				t.Fatal(err)
			}
			message := expectControlMessage(t, b, "a", payload, aAddress)
			if err := b.SendControl("a", []byte("return route not approved")); err == nil {
				t.Fatal("receiving a control message automatically approved its source")
			}
			// The service approves the observed source only after validating its
			// own generation nonce and return-route cookie.
			if err := b.ConfigureControlPeer("a", aKey.PublicKey().Bytes(), message.Endpoint); err != nil {
				t.Fatal(err)
			}
			// Reconfiguring from a roster without an endpoint must retain the
			// return route explicitly approved by the service.
			if err := b.ConfigureControlPeer("a", aKey.PublicKey().Bytes(), netip.AddrPort{}); err != nil {
				t.Fatal(err)
			}
			if err := b.SendControl("a", []byte("signed roster reply")); err != nil {
				t.Fatal(err)
			}
			expectControlMessage(t, a, "b", []byte("signed roster reply"), bAddress)
			if len(a.peers) != 0 || len(b.peers) != 0 || masked && (a.direct.mask.has("b") || b.direct.mask.has("a")) {
				t.Fatal("bootstrap unexpectedly installed a WireGuard data peer")
			}
		})
	}
}

func TestControlAuthenticationDomainsReplayAndBounds(t *testing.T) {
	a, b, _, _ := cryptoPair(t, "control-test")
	ka, err := deriveControlPeer(a.Bytes(), b.PublicKey().Bytes(), "control-test")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := deriveControlPeer(b.Bytes(), a.PublicKey().Bytes(), "control-test")
	if err != nil {
		t.Fatal(err)
	}
	if ka.sendTag != kb.recvTag || ka.recvTag != kb.sendTag || ka.sendTag == ka.recvTag {
		t.Fatal("directional control domains do not agree")
	}
	ma, mb := newControlTransport(), newControlTransport()
	initial := netip.MustParseAddrPort("192.0.2.1:1111")
	if err := ma.configure("b", ka, initial); err != nil {
		t.Fatal(err)
	}
	if err := mb.configure("a", kb, initial); err != nil {
		t.Fatal(err)
	}
	bind := conn.NewDefaultBind()
	from, err := bind.ParseEndpoint("127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("secret"), 100)
	packet, _, err := ma.seal("b", payload)
	if err != nil {
		t.Fatal(err)
	}
	if controlPacketLimit+48 > 1280 || bytes.Contains(packet, payload[:32]) {
		t.Fatal("control packet exceeds the minimum IPv6 MTU or exposes the payload")
	}
	second, _, err := ma.seal("b", payload)
	if err != nil || bytes.Equal(packet, second) {
		t.Fatalf("control nonce reused: %v", err)
	}
	for _, index := range []int{0, controlTagSize, len(packet) - 1} {
		modified := append([]byte(nil), packet...)
		modified[index] ^= 1
		mb.receive(modified, from)
	}
	for _, size := range []int{0, 1, controlTagSize, controlHeaderSize, controlHeaderSize + 16} {
		mb.receive(packet[:size], from)
	}
	mb.receive(append(append([]byte(nil), packet...), make([]byte, controlPacketLimit)...), from)
	mb.receive(packet, nil)
	if len(mb.messages) != 0 || kb.endpoint != initial {
		t.Fatal("unauthenticated or malformed packet was delivered or changed the endpoint")
	}
	if ma.receive(packet, from) || len(ma.messages) != 0 {
		t.Fatal("reflected packet was accepted")
	}
	other := newControlTransport()
	otherKey, err := deriveControlPeer(b.Bytes(), a.PublicKey().Bytes(), "different-network")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.configure("a", otherKey, initial); err != nil {
		t.Fatal(err)
	}
	if other.receive(packet, from) || len(other.messages) != 0 {
		t.Fatal("control message crossed the network domain")
	}
	outsider, _, _, _ := cryptoPair(t, "control-test")
	wrongPeer := newControlTransport()
	wrongKey, err := deriveControlPeer(b.Bytes(), outsider.PublicKey().Bytes(), "control-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongPeer.configure("a", wrongKey, initial); err != nil {
		t.Fatal(err)
	}
	if wrongPeer.receive(packet, from) || len(wrongPeer.messages) != 0 {
		t.Fatal("control message was accepted for another peer identity")
	}
	if !mb.receive(packet, from) {
		t.Fatal("valid control packet not recognized")
	}
	got := <-mb.messages
	if got.PeerID != "a" || !bytes.Equal(got.Payload, payload) || got.Endpoint.String() != from.DstToString() || kb.endpoint != initial {
		t.Fatal("valid authenticated control message was corrupted or automatically approved its return route")
	}
	if err := mb.configure("a", kb, got.Endpoint); err != nil {
		t.Fatal(err)
	}
	replaySource, err := bind.ParseEndpoint("127.0.0.1:3333")
	if err != nil {
		t.Fatal(err)
	}
	if !mb.receive(packet, replaySource) || len(mb.messages) != 0 || kb.endpoint != got.Endpoint {
		t.Fatal("recent replay was not rejected")
	}
	if kb.authIn.Load() != 1 || kb.rejected.Load() == 0 {
		t.Fatal("control diagnostics counted rejected messages as authenticated or lost rejection evidence")
	}
	for _, payload := range [][]byte{nil, make([]byte, ControlPayloadLimit+1)} {
		if _, _, err := ma.seal("b", payload); err == nil {
			t.Fatal("invalid outbound control size accepted")
		}
	}
	if _, _, err := ma.seal("unknown", []byte("x")); !errors.Is(err, ErrUnknownPeer) {
		t.Fatal("unknown control peer accepted")
	}
	if _, err := deriveControlPeer(a.Bytes(), a.PublicKey().Bytes(), "control-test"); err == nil {
		t.Fatal("local identity accepted as a control peer")
	}
	if _, err := deriveControlPeer(a.Bytes(), make([]byte, 32), "control-test"); err == nil {
		t.Fatal("low-order control peer accepted")
	}
	if err := mb.configure("a", ka, initial); err == nil {
		t.Fatal("an established control identity changed its public key")
	}
}

func TestControlQueueIsBoundedAndNeverBlocksReceiver(t *testing.T) {
	a, b, _, _ := cryptoPair(t, "control-test")
	ka, _ := deriveControlPeer(a.Bytes(), b.PublicKey().Bytes(), "control-test")
	kb, _ := deriveControlPeer(b.Bytes(), a.PublicKey().Bytes(), "control-test")
	ma, mb := newControlTransport(), newControlTransport()
	address := netip.MustParseAddrPort("127.0.0.1:2222")
	if err := ma.configure("b", ka, address); err != nil {
		t.Fatal(err)
	}
	if err := mb.configure("a", kb, address); err != nil {
		t.Fatal(err)
	}
	from, err := conn.NewDefaultBind().ParseEndpoint(address.String())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(mb.messages)+20; i++ {
		packet, _, err := ma.seal("b", []byte("bounded"))
		if err != nil || !mb.receive(packet, from) {
			t.Fatalf("control receive failed: %v", err)
		}
	}
	if len(mb.messages) != 128 {
		t.Fatalf("queue grew beyond its limit: %d", len(mb.messages))
	}
}

func TestControlRevocationRejectsPacketsAndPreservesOtherPeers(t *testing.T) {
	a, b, _, _ := cryptoPair(t, "control-test")
	c, _, _, _ := cryptoPair(t, "control-test")
	ka, _ := deriveControlPeer(a.Bytes(), b.PublicKey().Bytes(), "control-test")
	kb, _ := deriveControlPeer(b.Bytes(), a.PublicKey().Bytes(), "control-test")
	kc, _ := deriveControlPeer(c.Bytes(), b.PublicKey().Bytes(), "control-test")
	other, _ := deriveControlPeer(b.Bytes(), c.PublicKey().Bytes(), "control-test")
	ma, mb, mc := newControlTransport(), newControlTransport(), newControlTransport()
	address := netip.MustParseAddrPort("127.0.0.1:2222")
	for _, setup := range []struct {
		transport *controlTransport
		id        string
		peer      *controlPeer
	}{{ma, "b", ka}, {mb, "a", kb}, {mc, "b", kc}, {mb, "c", other}} {
		if err := setup.transport.configure(setup.id, setup.peer, address); err != nil {
			t.Fatal(err)
		}
	}
	from, err := conn.NewDefaultBind().ParseEndpoint(address.String())
	if err != nil {
		t.Fatal(err)
	}
	oldPacket, _, err := ma.seal("b", []byte("revoked"))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the public data-peer removal path without any host routes.
	node := &Tunnel{control: mb, policy: newPolicy(netip.MustParseAddr("10.233.75.1").AsSlice()),
		peers: map[string]*peer{"a": {ip: netip.MustParseAddr("10.233.75.2").AsSlice()}}}
	if err := node.RemovePeer("a"); err != nil {
		t.Fatal(err)
	}
	mb.remove("a") // idempotent, including unknown identities
	mb.remove("unknown")
	if mb.receive(oldPacket, from) || len(mb.messages) != 0 {
		t.Fatal("removed control identity still accepted a valid old packet")
	}
	if _, _, err := mb.seal("a", []byte("send after revocation")); !errors.Is(err, ErrUnknownPeer) {
		t.Fatal("removed control identity still accepted a send")
	}
	packet, _, err := mc.seal("b", []byte("other peer"))
	if err != nil || !mb.receive(packet, from) || len(mb.messages) != 1 {
		t.Fatalf("another control identity was affected by revocation: %v", err)
	}
}

type controlRecordingBind struct {
	conn.Bind
	sent chan struct{}
}

func (b *controlRecordingBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	err := b.Bind.Send(packets, endpoint)
	if err == nil {
		select {
		case b.sent <- struct{}{}:
		default:
		}
	}
	return err
}

func TestPendingControlPeerCannotCompleteWireGuardHandshake(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(fmt.Sprint("masked=", masked), func(t *testing.T) {
			ownerKey, guestKey, ownerCrypto, _ := cryptoPair(t, "control-test")
			newNode := func(key *ecdh.PrivateKey) (*Tunnel, *maskTestTUN, *controlRecordingBind, uint16) {
				recording := &controlRecordingBind{Bind: conn.NewDefaultBind(), sent: make(chan struct{}, 8)}
				control := newControlTransport()
				bind := &stunBind{Bind: recording, control: control}
				if masked {
					bind.mask = newUDPMask()
				}
				adapter := newMaskTestTUN()
				wg := device.NewDevice(adapter, bind, device.NewLogger(device.LogLevelSilent, ""))
				t.Cleanup(wg.Close)
				if err := wg.IpcSet("private_key=" + hex.EncodeToString(key.Bytes()) + "\nlisten_port=0\n"); err != nil {
					t.Fatal(err)
				}
				if err := wg.Up(); err != nil {
					t.Fatal(err)
				}
				config, err := wg.IpcGet()
				if err != nil {
					t.Fatal(err)
				}
				var port uint16
				for _, line := range strings.Split(config, "\n") {
					if value, ok := strings.CutPrefix(line, "listen_port="); ok {
						n, _ := strconv.ParseUint(value, 10, 16)
						port = uint16(n)
					}
				}
				if port == 0 {
					t.Fatal("WireGuard socket did not open")
				}
				node := &Tunnel{running: true, native: true, secureContext: "control-test", direct: bind, control: control, device: wg}
				copy(node.privateKey[:], key.Bytes())
				return node, adapter, recording, port
			}
			owner, ownerAdapter, ownerBind, ownerPort := newNode(ownerKey)
			guest, guestAdapter, _, guestPort := newNode(guestKey)
			ownerAddress := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ownerPort)
			guestAddress := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), guestPort)
			if err := owner.ConfigureControlPeer("guest", guestKey.PublicKey().Bytes(), guestAddress); err != nil {
				t.Fatal(err)
			}
			if err := guest.ConfigureControlPeer("owner", ownerKey.PublicKey().Bytes(), ownerAddress); err != nil {
				t.Fatal(err)
			}
			// The owner has approved this guest, but the guest has not received
			// its signed admission. Only the owner installs a WG data peer.
			if masked {
				if err := owner.direct.mask.add("guest", ownerCrypto); err != nil {
					t.Fatal(err)
				}
			}
			config := fmt.Sprintf("public_key=%x\npreshared_key=%x\nendpoint=%s\nallowed_ip=10.233.75.2/32\n",
				guestKey.PublicKey().Bytes(), ownerCrypto.preshared, directEndpoint("guest", guestAddress.String(), masked))
			if err := owner.device.IpcSet(config); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 32)
			packet[0], packet[8], packet[9] = 0x45, 64, 17
			binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
			copy(packet[12:16], []byte{10, 233, 75, 1})
			copy(packet[16:20], []byte{10, 233, 75, 2})
			copy(packet[28:], "data")
			ownerAdapter.outgoing <- packet
			select {
			case <-ownerBind.sent:
			case <-time.After(3 * time.Second):
				t.Fatal("owner did not attempt the WireGuard handshake")
			}
			if err := owner.SendControl("guest", []byte("admission metadata")); err != nil {
				t.Fatal(err)
			}
			expectControlMessage(t, guest, "owner", []byte("admission metadata"), ownerAddress)
			if err := guest.SendControl("owner", []byte("control acknowledged")); err != nil {
				t.Fatal(err)
			}
			expectControlMessage(t, owner, "guest", []byte("control acknowledged"), guestAddress)
			guestConfig, err := guest.device.IpcGet()
			if err != nil || strings.Contains(guestConfig, "public_key=") {
				t.Fatalf("pending control peer gained a WG data key: %v\n%s", err, guestConfig)
			}
			ownerConfig, err := owner.device.IpcGet()
			if err != nil || !strings.Contains(ownerConfig, "last_handshake_time_sec=0\n") {
				t.Fatalf("pending peer completed a WG handshake: %v\n%s", err, ownerConfig)
			}
			select {
			case <-guestAdapter.incoming:
				t.Fatal("pending peer received WG application data")
			default:
			}
		})
	}
}
