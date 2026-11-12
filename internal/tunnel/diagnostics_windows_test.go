//go:build windows

package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func diagnosticPacket(source, target net.IP, sourcePort, targetPort uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], source.To4())
	copy(packet[16:20], target.To4())
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	copy(packet[28:], payload)
	var checksum uint32
	for i := 0; i < 20; i += 2 {
		checksum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for checksum>>16 != 0 {
		checksum = checksum&65535 + checksum>>16
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(checksum))
	return packet
}

func diagnosticWG(t *testing.T, key *ecdh.PrivateKey, ip net.IP, masked bool) (*Tunnel, *maskTestTUN, uint16) {
	t.Helper()
	policy := newPolicy(ip)
	adapter := newMaskTestTUN()
	bind := &stunBind{Bind: conn.NewDefaultBind()}
	if masked {
		bind.mask = newUDPMask()
	}
	wg := device.NewDevice(&policyTUN{Device: adapter, policy: policy}, bind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(wg.Close)
	if err := wg.IpcSet("private_key=" + hex.EncodeToString(key.Bytes()) + "\nlisten_port=0\n"); err != nil {
		t.Fatal(err)
	}
	if err := wg.Up(); err != nil {
		t.Fatal(err)
	}
	raw, err := wg.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	for _, line := range strings.Split(raw, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			n, _ := strconv.ParseUint(value, 10, 16)
			port = uint16(n)
		}
	}
	if port == 0 {
		t.Fatal("WireGuard did not open a UDP socket")
	}
	node := &Tunnel{running: true, native: true, masked: masked, localIP: ip, policy: policy,
		device: wg, direct: bind, peers: make(map[string]*peer)}
	copy(node.privateKey[:], key.Bytes())
	return node, adapter, port
}

func diagnosticPeer(t *testing.T, node *Tunnel, key *ecdh.PrivateKey, ip net.IP, endpoint netip.AddrPort) {
	t.Helper()
	keys, err := derivePeerCrypto(node.privateKey[:], key.PublicKey().Bytes(), "diagnostics-test")
	if err != nil {
		t.Fatal(err)
	}
	if node.masked {
		if err := node.direct.mask.add("peer", keys); err != nil {
			t.Fatal(err)
		}
	}
	var route string
	if endpoint.IsValid() {
		route = "endpoint=" + directEndpoint("peer", endpoint.String(), node.masked) + "\n"
	}
	config := fmt.Sprintf("public_key=%x\npreshared_key=%x\n%sallowed_ip=%s/32\n", key.PublicKey().Bytes(), keys.preshared, route, ip)
	if err := node.device.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	p := &peer{id: "peer", ip: ip}
	copy(p.publicKey[:], key.PublicKey().Bytes())
	node.peers["peer"] = p
	node.policy.setPeer(ip, true)
}

func TestPolicyTUNProbePacketsCrossRealWireGuardBothDirections(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(fmt.Sprint("masked=", masked), func(t *testing.T) {
			aKey, bKey, _, _ := cryptoPair(t, "diagnostics-test")
			aIP, bIP := net.ParseIP("10.233.75.1").To4(), net.ParseIP("10.233.75.2").To4()
			a, aTun, aPort := diagnosticWG(t, aKey, aIP, masked)
			b, bTun, bPort := diagnosticWG(t, bKey, bIP, masked)
			diagnosticPeer(t, a, bKey, bIP, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bPort))
			diagnosticPeer(t, b, aKey, aIP, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), aPort))
			payload := append([]byte(probePrefix), bytes.Repeat([]byte{0xa6}, 32)...)
			request := diagnosticPacket(aIP, bIP, 52001, ProbePort, payload)
			// A spoofed local source must be dropped while the valid request
			// behind it still reaches the encrypted data plane.
			aTun.outgoing <- diagnosticPacket(net.IPv4(192, 168, 1, 3), bIP, 52001, ProbePort, payload)
			aTun.outgoing <- request
			select {
			case packet := <-bTun.incoming:
				if !bytes.Equal(packet, request) {
					t.Fatal("request changed across policy and WireGuard")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("request did not reach peer TUN")
			}
			reply := diagnosticPacket(bIP, aIP, ProbePort, 52001, payload)
			bTun.outgoing <- reply
			select {
			case packet := <-aTun.incoming:
				if !bytes.Equal(packet, reply) {
					t.Fatal("reply changed across policy and WireGuard")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("reply did not reach original TUN")
			}
			for _, node := range []*Tunnel{a, b} {
				d, err := node.Diagnostics("peer")
				if err != nil || d.OutboundPackets != 1 || d.InboundPackets != 1 || d.WriteErrors != 0 {
					t.Fatalf("packet diagnostics do not reflect the real data path: %+v, %v", d, err)
				}
				stats, err := node.Stats("peer")
				if err != nil || stats.LastHandshake.IsZero() || stats.TxBytes == 0 || stats.RxBytes == 0 {
					t.Fatalf("missing real WG traffic: %+v, %v", stats, err)
				}
			}
			d, _ := a.Diagnostics("peer")
			if d.OutboundDrops != 1 || d.PolicyDrops != 1 {
				t.Fatalf("spoofed-source drop was not counted: %+v", d)
			}
		})
	}
}

type diagnosticFailTUN struct {
	*maskTestTUN
	failure error
}

func (f *diagnosticFailTUN) Write(_ [][]byte, _ int) (int, error) { return 0, f.failure }

func TestPolicyTUNRecordsIncomingWriteFailuresWithoutReportingDelivery(t *testing.T) {
	for _, failure := range []error{errors.New("test Wintun write failed"), nil} {
		policy := newPolicy(net.ParseIP("10.233.75.1"))
		peerIP := net.ParseIP("10.233.75.2")
		policy.setPeer(peerIP, true)
		adapter := &diagnosticFailTUN{maskTestTUN: newMaskTestTUN(), failure: failure}
		defer adapter.Close()
		wrapped := &policyTUN{Device: adapter, policy: policy}
		packet := diagnosticPacket(peerIP, net.ParseIP("10.233.75.1"), ProbePort, 52001, []byte("probe"))
		buffer := append(make([]byte, 16), packet...)
		if _, err := wrapped.Write([][]byte{buffer}, 16); err == nil || failure == nil && !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("write failure lost: %v", err)
		}
		d := policy.diagnostics(peerIP)
		if d.InboundPackets != 1 || d.WriteErrors != 1 || d.LastWriteError == "" || d.LastWriteErrorAt.IsZero() {
			t.Fatalf("write diagnostics missing: %+v", d)
		}
		if d.EchoRequests != 0 || d.EchoReplies != 0 {
			t.Fatal("failed adapter write was reported as a socket delivery")
		}
	}
}

func TestEchoSocketRepliesOnlyToApprovedExactProbe(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var approved atomic.Bool
	approved.Store(true)
	policy := newPolicy(net.IPv4(127, 0, 0, 2))
	policy.setPeer(net.IPv4(127, 0, 0, 1), true)
	observed := make(chan struct{}, 1)
	go serveEcho(server, done, func(net.IP) bool { return approved.Load() }, func(ip net.IP, ok bool) { policy.recordEcho(ip, ok); observed <- struct{}{} }, policy.recordEchoReadError)
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("echo did not stop")
		}
	})
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := append([]byte(probePrefix), bytes.Repeat([]byte{0xb9}, 32)...)
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload)+2)
	n, err := client.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("valid nonce echo failed: %v", err)
	}
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("echo observation missing")
	}
	for _, invalid := range [][]byte{payload[:len(payload)-1], append(append([]byte(nil), payload...), 0), bytes.Repeat([]byte{'x'}, len(payload)), bytes.Repeat([]byte{0xab}, 128)} {
		if err := client.SetReadDeadline(time.Now().Add(80 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(invalid); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Read(buffer); err == nil {
			t.Fatal("malformed probe received a reply")
		}
	}
	approved.Store(false)
	if err := client.SetReadDeadline(time.Now().Add(80 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("unapproved source received a reply")
	}
	d := policy.diagnostics(net.IPv4(127, 0, 0, 1))
	if d.EchoRequests != 1 || d.EchoReplies != 1 {
		t.Fatalf("echo counts include invalid probes: %+v", d)
	}
	if d.EchoReadErrors != 1 || d.LastEchoReadError == "" || d.LastEchoReadErrorAt.IsZero() {
		t.Fatalf("oversized UDP error was not recorded: %+v", d)
	}
	approved.Store(true)
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("malformed packet stopped the echo responder: %v", err)
	}
}

func TestEchoReadErrorClassification(t *testing.T) {
	for _, err := range []error{windows.WSAEMSGSIZE, windows.WSAECONNRESET, windows.WSAENETRESET} {
		if !recoverableEchoReadError(fmt.Errorf("wrapped UDP read: %w", err)) {
			t.Fatalf("recoverable Windows UDP error classified as fatal: %v", err)
		}
	}
	for _, err := range []error{nil, net.ErrClosed, windows.WSAEACCES, windows.WSAENOTSOCK, errors.New("permanent failure")} {
		if recoverableEchoReadError(err) {
			t.Fatalf("permanent/closed error would retry forever: %v", err)
		}
	}
}

func TestProbeReportsBadReplyAndRejectsEchoWithoutWireGuardTraffic(t *testing.T) {
	for _, badReply := range []bool{true, false} {
		t.Run(fmt.Sprint("bad_reply=", badReply), func(t *testing.T) {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			remote, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			node, _, _ := diagnosticWG(t, key, net.IPv4(127, 0, 0, 1), false)
			diagnosticPeer(t, node, remote, net.IPv4(127, 0, 0, 2), netip.AddrPort{})
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: ProbePort})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				buffer := make([]byte, 128)
				n, from, err := server.ReadFromUDP(buffer)
				if err == nil {
					if badReply {
						buffer[0] ^= 1
					}
					_, _ = server.WriteToUDP(buffer[:n], from)
				}
			}()
			_, err = node.Probe("peer")
			if !errors.Is(err, ErrProbeFailed) {
				t.Fatalf("probe failed without sentinel: %v", err)
			}
			stage := "stage=handshake_missing"
			if badReply {
				stage = "stage=bad_reply"
			}
			if !strings.Contains(err.Error(), stage) {
				t.Fatalf("wrong probe failure stage: %v", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("test responder did not stop")
			}
		})
	}
}

func TestProbeStatsRequireRecentHandshakeAndBothTrafficDirections(t *testing.T) {
	now := time.Now()
	before := PeerStats{TxBytes: 10, RxBytes: 20}
	for _, test := range []struct {
		name  string
		after PeerStats
		stage string
	}{
		{"healthy", PeerStats{LastHandshake: now, TxBytes: 11, RxBytes: 21}, ""},
		{"missing", PeerStats{TxBytes: 11, RxBytes: 21}, "handshake_missing"},
		{"stale", PeerStats{LastHandshake: now.Add(-3*time.Minute - time.Second), TxBytes: 11, RxBytes: 21}, "stale_handshake"},
		{"no_tx", PeerStats{LastHandshake: now, TxBytes: 10, RxBytes: 21}, "no_stats_delta"},
		{"no_rx", PeerStats{LastHandshake: now, TxBytes: 11, RxBytes: 20}, "no_stats_delta"},
		{"counter_reset", PeerStats{LastHandshake: now, TxBytes: 1, RxBytes: 2}, "no_stats_delta"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateProbeStats(before, test.after, now)
			if test.stage == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrProbeFailed) || !strings.Contains(err.Error(), "stage="+test.stage) {
				t.Fatalf("wrong statistics failure: %v", err)
			}
		})
	}
}
