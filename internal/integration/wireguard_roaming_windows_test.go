//go:build windows

package integration

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// No Wintun driver, coordinator, or network route is needed. Exercise the
// same native UDP bind as the serverless application and move a peer's port.
func TestNativeWireGuardLearnsChangedEndpoint(t *testing.T) {
	newDevice := func() (*device.Device, *memoryTUN, string) {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		iface := newTUN()
		wg := device.NewDevice(iface, conn.NewDefaultBind(), &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf})
		t.Cleanup(wg.Close)
		if err := wg.IpcSet("private_key=" + hex.EncodeToString(key.Bytes()) + "\nlisten_port=0\n"); err != nil {
			t.Fatal(err)
		}
		if err := wg.Up(); err != nil {
			t.Fatal(err)
		}
		return wg, iface, hex.EncodeToString(key.PublicKey().Bytes())
	}
	read := func(wg *device.Device, key string) string {
		config, err := wg.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(config, "\n") {
			if value, ok := strings.CutPrefix(line, key+"="); ok {
				return value
			}
		}
		return ""
	}
	a, tunA, keyA := newDevice()
	b, tunB, keyB := newDevice()
	portA, portB := read(a, "listen_port"), read(b, "listen_port")
	if portA == "" || portB == "" {
		t.Fatal("native bind did not expose its UDP port")
	}
	if err := a.IpcSet("public_key=" + keyB + "\nallowed_ip=172.30.81.2/32\n"); err != nil {
		t.Fatal(err)
	}
	if err := b.IpcSet("public_key=" + keyA + "\nallowed_ip=172.30.81.1/32\nendpoint=127.0.0.1:" + portA + "\n"); err != nil {
		t.Fatal(err)
	}
	transfer := func(from, to *memoryTUN, src, dst [4]byte, label string) {
		packet := ipv4UDP(src, dst, []byte(label))
		from.outgoing <- packet
		select {
		case received := <-to.incoming:
			if !bytes.Equal(received, packet) {
				t.Fatalf("unexpected packet for %s", label)
			}
		case <-time.After(6 * time.Second):
			t.Fatalf("no encrypted transport for %s", label)
		}
	}
	ipA, ipB := [4]byte{172, 30, 81, 1}, [4]byte{172, 30, 81, 2}
	transfer(tunB, tunA, ipB, ipA, "initial endpoint")
	if got := read(a, "endpoint"); got != "127.0.0.1:"+portB {
		t.Fatalf("listener did not learn first endpoint: %s", got)
	}
	// Select an unused port while the previous WireGuard socket is still bound.
	hold, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_, newPort, _ := net.SplitHostPort(hold.LocalAddr().String())
	_ = hold.Close()
	if newPort == portB {
		t.Fatal("expected a different test port")
	}
	if err := b.IpcSet("listen_port=" + newPort + "\n"); err != nil {
		t.Fatal(err)
	}
	transfer(tunB, tunA, ipB, ipA, "new endpoint")
	if got := read(a, "endpoint"); got != "127.0.0.1:"+newPort {
		t.Fatalf("listener retained stale endpoint: %s", got)
	}
	transfer(tunA, tunB, ipA, ipB, "return after roaming")
}
