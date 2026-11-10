//go:build windows

package peerice

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"directlan/internal/platform"
)

func TestLocalDirectDatagrams(t *testing.T) {
	adapters, err := platform.PhysicalCandidates()
	if err != nil || len(adapters) == 0 {
		t.Skip("no active physical adapter available")
	}
	var cfg Config
	for _, adapter := range adapters {
		for _, address := range adapter.Addresses {
			ip := net.ParseIP(address)
			if ip.To4() != nil {
				cfg = Config{InterfaceName: adapter.Name, LocalIP: ip}
				break
			}
		}
		if cfg.LocalIP != nil {
			break
		}
	}
	if cfg.LocalIP == nil {
		t.Skip("no physical IPv4 address")
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(cfg)
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
		conn net.Conn
		err  error
	}
	results := make(chan result, 2)
	go func() { c, e := a.Connect(ctx, ob, true); results <- result{c, e} }()
	go func() { c, e := b.Connect(ctx, oa, false); results <- result{c, e} }()
	r1, r2 := <-results, <-results
	if r1.err != nil || r2.err != nil {
		t.Fatalf("ICE: %v / %v", r1.err, r2.err)
	}
	payload := []byte("directlan-local-ice-datagram")
	if _, err := r1.conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1500)
	read := make(chan result, 1)
	go func() {
		n, e := r2.conn.Read(buffer)
		if e == nil && !bytes.Equal(payload, buffer[:n]) {
			e = net.ErrClosed
		}
		read <- result{err: e}
	}()
	select {
	case got := <-read:
		if got.err != nil {
			t.Fatal(got.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
