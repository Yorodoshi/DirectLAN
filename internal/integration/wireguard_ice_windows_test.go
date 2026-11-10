//go:build windows

package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"directlan/internal/icebind"
	"directlan/internal/peerice"
	"directlan/internal/platform"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type memoryTUN struct {
	outgoing, incoming chan []byte
	stop               chan struct{}
	events             chan tun.Event
	once               sync.Once
}

func newTUN() *memoryTUN {
	return &memoryTUN{outgoing: make(chan []byte, 8), incoming: make(chan []byte, 8), stop: make(chan struct{}), events: make(chan tun.Event)}
}
func (*memoryTUN) File() *os.File { return nil }
func (m *memoryTUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-m.stop:
		return 0, net.ErrClosed
	case p := <-m.outgoing:
		copy(packets[0][offset:], p)
		sizes[0] = len(p)
		return 1, nil
	}
}
func (m *memoryTUN) Write(packets [][]byte, offset int) (int, error) {
	for _, p := range packets {
		data := append([]byte(nil), p[offset:]...)
		select {
		case <-m.stop:
			return 0, net.ErrClosed
		case m.incoming <- data:
		}
	}
	return len(packets), nil
}
func (*memoryTUN) MTU() (int, error)          { return 1280, nil }
func (*memoryTUN) Name() (string, error)      { return "memory", nil }
func (m *memoryTUN) Events() <-chan tun.Event { return m.events }
func (m *memoryTUN) Close() error             { m.once.Do(func() { close(m.stop); close(m.events) }); return nil }
func (*memoryTUN) BatchSize() int             { return 1 }

func TestWireGuardOverICEAndSourceACL(t *testing.T) {
	adapters, err := platform.PhysicalCandidates()
	if err != nil {
		t.Fatal(err)
	}
	var cfg peerice.Config
	for _, a := range adapters {
		for _, raw := range a.Addresses {
			ip := net.ParseIP(raw)
			if ip.To4() != nil {
				cfg = peerice.Config{InterfaceName: a.Name, LocalIP: ip}
				break
			}
		}
		if cfg.LocalIP != nil {
			break
		}
	}
	if cfg.LocalIP == nil {
		t.Skip("no active physical IPv4 adapter")
	}
	a, err := peerice.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := peerice.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	oa, err := a.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ob, err := b.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type result struct {
		c net.Conn
		e error
	}
	ac := make(chan result, 1)
	go func() { c, e := a.Connect(ctx, ob, true); ac <- result{c, e} }()
	bc, err := b.Connect(ctx, oa, false)
	if err != nil {
		t.Fatal(err)
	}
	ar := <-ac
	if ar.e != nil {
		t.Fatal(ar.e)
	}
	keyA, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tunA, tunB := newTUN(), newTUN()
	bindA, bindB := icebind.New(), icebind.New()
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	wgA, wgB := device.NewDevice(tunA, bindA, logger), device.NewDevice(tunB, bindB, logger)
	defer wgA.Close()
	defer wgB.Close()
	for _, p := range []struct {
		wg  *device.Device
		key []byte
	}{{wgA, keyA.Bytes()}, {wgB, keyB.Bytes()}} {
		if err := p.wg.IpcSet("private_key=" + hex.EncodeToString(p.key) + "\n"); err != nil {
			t.Fatal(err)
		}
		if err := p.wg.Up(); err != nil {
			t.Fatal(err)
		}
	}
	if err := bindA.Attach("peerB", ar.c); err != nil {
		t.Fatal(err)
	}
	if err := bindB.Attach("peerA", bc); err != nil {
		t.Fatal(err)
	}
	if err := wgA.IpcSet("public_key=" + hex.EncodeToString(keyB.PublicKey().Bytes()) + "\nendpoint=peerB\nallowed_ip=10.233.75.2/32\n"); err != nil {
		t.Fatal(err)
	}
	if err := wgB.IpcSet("public_key=" + hex.EncodeToString(keyA.PublicKey().Bytes()) + "\nendpoint=peerA\nallowed_ip=10.233.75.1/32\n"); err != nil {
		t.Fatal(err)
	}
	packet := ipv4UDP([4]byte{10, 233, 75, 1}, [4]byte{10, 233, 75, 2}, []byte("authenticated application payload"))
	tunA.outgoing <- packet
	select {
	case received := <-tunB.incoming:
		if !bytes.Equal(packet, received) {
			t.Fatal("decrypted packet differs")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WireGuard over ICE did not deliver packet")
	}
	spoofed := ipv4UDP([4]byte{10, 233, 75, 99}, [4]byte{10, 233, 75, 2}, []byte("spoofed source"))
	tunA.outgoing <- spoofed
	select {
	case <-tunB.incoming:
		t.Fatal("WireGuard accepted unassigned source IP")
	case <-time.After(400 * time.Millisecond):
	}
}

func ipv4UDP(source, destination [4]byte, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], source[:])
	copy(p[16:20], destination[:])
	binary.BigEndian.PutUint16(p[20:22], 12345)
	binary.BigEndian.PutUint16(p[22:24], 23456)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
