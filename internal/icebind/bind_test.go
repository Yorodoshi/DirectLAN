package icebind

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	wgconn "golang.zx2c4.com/wireguard/conn"
)

type datagramConn struct {
	in     chan []byte
	other  *datagramConn
	closed chan struct{}
	once   sync.Once
	local  *net.UDPAddr
	remote *net.UDPAddr
}

func datagramPair() (*datagramConn, *datagramConn) {
	a := &datagramConn{in: make(chan []byte, 128), closed: make(chan struct{}), local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}, remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}}
	b := &datagramConn{in: make(chan []byte, 128), closed: make(chan struct{}), local: a.remote, remote: a.local}
	a.other, b.other = b, a
	return a, b
}

func (c *datagramConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case packet := <-c.in:
		return copy(p, packet), nil
	}
}

func (c *datagramConn) Write(p []byte) (int, error) {
	packet := bytes.Clone(p)
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.other.closed:
		return 0, net.ErrClosed
	case c.other.in <- packet:
		return len(p), nil
	}
}

func (c *datagramConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *datagramConn) LocalAddr() net.Addr              { return c.local }
func (c *datagramConn) RemoteAddr() net.Addr             { return c.remote }
func (c *datagramConn) SetDeadline(time.Time) error      { return nil }
func (c *datagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *datagramConn) SetWriteDeadline(time.Time) error { return nil }

func receive(t *testing.T, fn wgconn.ReceiveFunc) ([]byte, wgconn.Endpoint, error) {
	t.Helper()
	type result struct {
		data []byte
		ep   wgconn.Endpoint
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		packets := [][]byte{make([]byte, maxDatagram)}
		sizes := make([]int, 1)
		eps := make([]wgconn.Endpoint, 1)
		n, err := fn(packets, sizes, eps)
		if n != 1 {
			ch <- result{err: err}
			return
		}
		ch <- result{data: bytes.Clone(packets[0][:sizes[0]]), ep: eps[0], err: err}
	}()
	select {
	case got := <-ch:
		return got.data, got.ep, got.err
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not finish")
		return nil, nil, nil
	}
}

func TestDatagramsAndEndpointIdentity(t *testing.T) {
	b := New()
	local, remote := datagramPair()
	if err := b.Attach("peer-a", local); err != nil {
		t.Fatal(err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(fns) != 1 || b.BatchSize() != 1 {
		t.Fatalf("unexpected receive functions or batch size: %d / %d", len(fns), b.BatchSize())
	}
	request := []byte{0, 1, 2, 3, 254, 255}
	if _, err := remote.Write(request); err != nil {
		t.Fatal(err)
	}
	got, ep, err := receive(t, fns[0])
	if err != nil || !bytes.Equal(got, request) {
		t.Fatalf("received %x, err %v", got, err)
	}
	parsed, err := b.ParseEndpoint("peer-a")
	if err != nil || ep != parsed || ep.DstToString() != "peer-a" {
		t.Fatalf("endpoint mismatch: %v, %v", ep, err)
	}
	if !ep.DstIP().Is4() || !ep.SrcIP().Is4() || len(ep.DstToBytes()) == 0 {
		t.Fatalf("endpoint lacks address identity: %v", ep)
	}
	reply := []byte{9, 8, 7, 6}
	if err := b.Send([][]byte{reply}, ep); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := remote.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], reply) {
		t.Fatalf("sent %x, err %v", buf[:n], err)
	}
}

func TestForeignAndStaleEndpointRejected(t *testing.T) {
	b := New()
	oldLocal, _ := datagramPair()
	if err := b.Attach("same-id", oldLocal); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	old, err := b.ParseEndpoint("same-id")
	if err != nil {
		t.Fatal(err)
	}
	other := New()
	if err := other.Send([][]byte{{1}}, old); !errors.Is(err, wgconn.ErrWrongEndpointType) {
		t.Fatalf("foreign endpoint accepted: %v", err)
	}
	b.Detach("same-id")
	newLocal, _ := datagramPair()
	if err := b.Attach("same-id", newLocal); err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, old); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("stale endpoint accepted: %v", err)
	}
	if _, err := b.ParseEndpoint("missing"); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("unknown endpoint accepted: %v", err)
	}
}

func TestQueueIsBounded(t *testing.T) {
	b := New()
	local, remote := datagramPair()
	if err := b.Attach("peer-a", local); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	packet := make([]byte, maxDatagram)
	for range 64 {
		if _, err := remote.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for b.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if b.Dropped() == 0 {
		t.Fatal("full queue did not drop packets")
	}
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	state.mu.Lock()
	queued := state.queuedBytes
	state.mu.Unlock()
	if queued > maxQueuedBytes {
		t.Fatalf("queue exceeds byte budget: %d", queued)
	}
}

func TestCloseUnblocksAndAllowsReopen(t *testing.T) {
	b := New()
	local, _ := datagramPair()
	if err := b.Attach("peer-a", local); err != nil {
		t.Fatal(err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		packets := [][]byte{make([]byte, 1500)}
		_, err := fns[0](packets, make([]int, 1), make([]wgconn.Endpoint, 1))
		done <- err
	}()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not unblock receive")
	}
	if _, err := b.ParseEndpoint("peer-a"); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("closed peer remained attached: %v", err)
	}
	newLocal, newRemote := datagramPair()
	if err := b.Attach("peer-a", newLocal); err != nil {
		t.Fatal(err)
	}
	fns, _, err = b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := newRemote.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	got, _, err := receive(t, fns[0])
	if err != nil || !bytes.Equal(got, []byte{42}) {
		t.Fatalf("reopened bind received %v, err %v", got, err)
	}
}

func TestValidationAndMark(t *testing.T) {
	b := New()
	local, _ := datagramPair()
	if err := b.Attach("bad\nendpoint=x", local); !errors.Is(err, ErrInvalidPeerID) {
		t.Fatalf("unsafe ID accepted: %v", err)
	}
	if err := b.Attach("peer-a", local); err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("peer-a", local); !errors.Is(err, ErrPeerExists) {
		t.Fatalf("duplicate ID accepted: %v", err)
	}
	if err := b.SetMark(123); !errors.Is(err, ErrUnsupportedMark) {
		t.Fatalf("mark silently accepted: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}
