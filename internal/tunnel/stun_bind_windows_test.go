//go:build windows

package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"golang.zx2c4.com/wireguard/conn"
)

func TestSTUNUsesWireGuardPort(t *testing.T) {
	t.Run("legacy", func(t *testing.T) { testSTUNUsesWireGuardPort(t, nil) })
	t.Run("masked", func(t *testing.T) { testSTUNUsesWireGuardPort(t, newUDPMask()) })
}

func testSTUNUsesWireGuardPort(t *testing.T, mask *udpMask) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	bind := &stunBind{Bind: conn.NewDefaultBind(), mask: mask}
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	packets, sizes, endpoints := [][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1)
	received := make(chan error, 1)
	go func() {
		_, err := receivers[0](packets, sizes, endpoints)
		received <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan netip.AddrPort, 1)
	go func() {
		mapped, _ := bind.discover(ctx, server.LocalAddr().(*net.UDPAddr).AddrPort())
		result <- mapped
	}()

	var packet [1500]byte
	n, from, err := server.ReadFromUDPAddrPort(packet[:])
	if err != nil {
		t.Fatal(err)
	}
	if from.Port() != port {
		t.Fatalf("STUN used port %d, want WireGuard port %d", from.Port(), port)
	}
	var request stun.Message
	if err := stun.Decode(packet[:n], &request); err != nil {
		t.Fatal(err)
	}
	response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
		&stun.XORMappedAddress{IP: from.Addr().AsSlice(), Port: int(from.Port())}, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteToUDPAddrPort(response.Raw, from); err != nil {
		t.Fatal(err)
	}
	if mapped := <-result; mapped != from {
		t.Fatalf("STUN returned %s, want %s", mapped, from)
	}
	if err := <-received; err != nil || sizes[0] != 0 {
		t.Fatalf("STUN response reached the WireGuard receiver: size %d, error %v", sizes[0], err)
	}
}
