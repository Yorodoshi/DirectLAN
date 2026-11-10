//go:build windows

package tunnel

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func testTunnel(t *testing.T) *Tunnel {
	t.Helper()
	_, cidr, err := net.ParseCIDR("10.213.47.0/24")
	if err != nil {
		t.Fatal(err)
	}
	tun, err := New(bytes.Repeat([]byte{1}, 32), net.ParseIP("10.213.47.1"), cidr)
	if err != nil {
		t.Fatal(err)
	}
	return tun
}

func TestNewRejectsUnsafeOverlay(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.213.47.0/24")
	if _, err := New(make([]byte, 32), net.ParseIP("10.213.47.1"), cidr); err == nil {
		t.Fatal("zero private key accepted")
	}
	if _, err := New(bytes.Repeat([]byte{1}, 32), net.ParseIP("10.213.47.0"), cidr); err == nil {
		t.Fatal("network address accepted")
	}
	if _, err := New(bytes.Repeat([]byte{1}, 32), net.ParseIP("10.213.47.255"), cidr); err == nil {
		t.Fatal("broadcast address accepted")
	}
	_, publicCIDR, _ := net.ParseCIDR("8.0.0.0/8")
	if _, err := New(bytes.Repeat([]byte{1}, 32), net.ParseIP("8.8.8.8"), publicCIDR); err == nil {
		t.Fatal("public overlay accepted")
	}
}

func TestPeerValidationAndStop(t *testing.T) {
	tun := testTunnel(t)
	local, remote := net.Pipe()
	defer remote.Close()
	if err := tun.AddPeer("peer-a", bytes.Repeat([]byte{2}, 32), net.ParseIP("10.213.47.2"), local); err != nil {
		t.Fatal(err)
	}
	otherLocal, otherRemote := net.Pipe()
	defer otherLocal.Close()
	defer otherRemote.Close()
	if err := tun.AddPeer("peer-b", bytes.Repeat([]byte{3}, 32), net.ParseIP("10.213.47.2"), otherLocal); err == nil {
		t.Fatal("duplicate overlay IP accepted")
	}
	if _, err := tun.Probe("peer-a"); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("probe before Start returned %v", err)
	}
	if err := tun.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Stop(); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
	if err := tun.AddPeer("peer-b", bytes.Repeat([]byte{3}, 32), net.ParseIP("10.213.47.3"), otherLocal); !errors.Is(err, ErrStopped) {
		t.Fatalf("peer added after Stop: %v", err)
	}
}

func TestParsePeerStats(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	keyHex := "0404040404040404040404040404040404040404040404040404040404040404"
	if len(key) != 32 {
		t.Fatal("bad fixture")
	}
	raw := "private_key=secret\npublic_key=deadbeef\nlast_handshake_time_sec=1\ntx_bytes=1\nrx_bytes=2\n" +
		"public_key=" + keyHex + "\nlast_handshake_time_sec=1790000000\ntx_bytes=12\nrx_bytes=34\n"
	stats, err := parsePeerStats(raw, keyHex)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TxBytes != 12 || stats.RxBytes != 34 || !stats.LastHandshake.Equal(time.Unix(1790000000, 0)) {
		t.Fatalf("wrong peer stats: %+v", stats)
	}
	if _, err := parsePeerStats(raw, "missing"); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("missing peer returned %v", err)
	}
}
