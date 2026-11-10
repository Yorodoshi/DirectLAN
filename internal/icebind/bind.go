// Package icebind adapts established ICE datagram connections to wireguard-go.
//
// The caller owns ICE negotiation. Attach transfers ownership of an established
// connection to Bind; Detach and Close close it. A closed Bind can be opened
// again after new connections have been attached.
package icebind

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	wgconn "golang.zx2c4.com/wireguard/conn"
)

const (
	queueCapacity    = 256
	maxQueuedBytes   = 1 << 20
	maxDatagram      = 65535
	pooledBufferSize = 2048
)

var (
	ErrInvalidPeerID   = errors.New("invalid peer ID")
	ErrPeerExists      = errors.New("peer already attached")
	ErrUnknownPeer     = errors.New("peer is not attached")
	ErrClosing         = errors.New("bind is closing")
	ErrUnsupportedMark = errors.New("socket mark is unsupported by ICE bind")
	ErrPacketTooLarge  = errors.New("datagram exceeds maximum size")
	ErrShortBuffer     = errors.New("receive buffer is too small")
)

// Bind is a single wireguard-go transport carrying one ICE connection per peer.
// Endpoints are bound to an attachment instance: an endpoint from a detached
// connection cannot silently address a later connection with the same ID.
type Bind struct {
	mu      sync.Mutex
	peers   map[string]*peerConn
	state   *runState
	closing chan struct{}
	dropped atomic.Uint64
	pool    sync.Pool
}

type peerConn struct {
	id       string
	conn     net.Conn
	endpoint *endpoint
	active   atomic.Bool
}

type queuedPacket struct {
	peer    *peerConn
	data    []byte
	backing *[pooledBufferSize]byte
}

type runState struct {
	queue       chan queuedPacket
	stop        chan struct{}
	mu          sync.Mutex
	closed      bool
	queuedBytes int
	workers     sync.WaitGroup
}

type endpoint struct {
	owner  *Bind
	peerID string
	local  netip.AddrPort
	remote netip.AddrPort
	cookie [32]byte
}

var _ wgconn.Bind = (*Bind)(nil)
var _ wgconn.Endpoint = (*endpoint)(nil)

func New() *Bind {
	b := &Bind{peers: make(map[string]*peerConn)}
	b.pool.New = func() any { return new([pooledBufferSize]byte) }
	return b
}

// Attach accepts an ICE connection that preserves datagram boundaries. The
// connection must have exclusive use by Bind after this call succeeds.
func (b *Bind) Attach(peerID string, conn net.Conn) error {
	if !validPeerID(peerID) {
		return ErrInvalidPeerID
	}
	if conn == nil {
		return errors.New("nil ICE connection")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing != nil {
		return ErrClosing
	}
	if _, exists := b.peers[peerID]; exists {
		return ErrPeerExists
	}
	p := &peerConn{id: peerID, conn: conn}
	p.endpoint = makeEndpoint(b, peerID, conn)
	p.active.Store(true)
	b.peers[peerID] = p
	if b.state != nil {
		b.startReaderLocked(p, b.state)
	}
	return nil
}

// Detach closes the connection for peerID. It is safe to call repeatedly.
func (b *Bind) Detach(peerID string) {
	b.mu.Lock()
	p := b.peers[peerID]
	if p != nil {
		delete(b.peers, peerID)
		p.active.Store(false)
	}
	b.mu.Unlock()
	if p != nil {
		_ = p.conn.Close()
	}
}

func (b *Bind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing != nil {
		return nil, 0, ErrClosing
	}
	if b.state != nil {
		return nil, 0, wgconn.ErrBindAlreadyOpen
	}
	state := &runState{
		queue: make(chan queuedPacket, queueCapacity),
		stop:  make(chan struct{}),
	}
	b.state = state
	for _, p := range b.peers {
		b.startReaderLocked(p, state)
	}
	return []wgconn.ReceiveFunc{b.receiveFunc(state)}, port, nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	if b.closing != nil {
		done := b.closing
		b.mu.Unlock()
		<-done
		return nil
	}
	done := make(chan struct{})
	b.closing = done
	state := b.state
	b.state = nil
	peers := b.peers
	b.peers = make(map[string]*peerConn)
	if state != nil {
		state.mu.Lock()
		state.closed = true
		close(state.stop)
		state.mu.Unlock()
	}
	for _, p := range peers {
		p.active.Store(false)
	}
	b.mu.Unlock()

	var closeErrors []error
	for _, p := range peers {
		if err := p.conn.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close peer %s: %w", p.id, err))
		}
	}
	if state != nil {
		state.workers.Wait()
	}

	b.mu.Lock()
	b.closing = nil
	close(done)
	b.mu.Unlock()
	return errors.Join(closeErrors...)
}

// Send writes each WireGuard datagram without changing its contents.
func (b *Bind) Send(bufs [][]byte, ep wgconn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok || e.owner != b {
		return wgconn.ErrWrongEndpointType
	}
	if len(bufs) > b.BatchSize() {
		return fmt.Errorf("batch of %d exceeds size %d", len(bufs), b.BatchSize())
	}
	b.mu.Lock()
	p := b.peers[e.peerID]
	open := b.state != nil && b.closing == nil
	if p == nil || p.endpoint != e {
		b.mu.Unlock()
		return ErrUnknownPeer
	}
	b.mu.Unlock()
	if !open || !p.active.Load() {
		return net.ErrClosed
	}
	for _, data := range bufs {
		if len(data) > maxDatagram {
			return ErrPacketTooLarge
		}
		if !p.active.Load() {
			return net.ErrClosed
		}
		n, err := p.conn.Write(data)
		if err != nil {
			return err
		}
		if n != len(data) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (b *Bind) ParseEndpoint(peerID string) (wgconn.Endpoint, error) {
	if !validPeerID(peerID) {
		return nil, ErrInvalidPeerID
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.peers[peerID]
	if p == nil || b.closing != nil {
		return nil, ErrUnknownPeer
	}
	return p.endpoint, nil
}

func (*Bind) BatchSize() int { return 1 }

// SetMark fails closed for nonzero marks. Windows ICE sockets do not implement
// SO_MARK; silently accepting one would misrepresent the route in use.
func (*Bind) SetMark(mark uint32) error {
	if mark != 0 {
		return ErrUnsupportedMark
	}
	return nil
}

// Dropped returns the number of datagrams rejected by the bounded input queue.
func (b *Bind) Dropped() uint64 { return b.dropped.Load() }

func (b *Bind) startReaderLocked(p *peerConn, state *runState) {
	state.workers.Add(1)
	go b.readPeer(p, state)
}

func (b *Bind) readPeer(p *peerConn, state *runState) {
	defer state.workers.Done()
	buf := make([]byte, maxDatagram+1)
	for p.active.Load() {
		n, err := p.conn.Read(buf)
		if err != nil {
			b.detachIfCurrent(p)
			return
		}
		if n == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		if n > maxDatagram {
			b.dropped.Add(1)
			continue
		}
		item := queuedPacket{peer: p}
		if n <= pooledBufferSize {
			item.backing = b.pool.Get().(*[pooledBufferSize]byte)
			item.data = item.backing[:n]
		} else {
			item.data = make([]byte, n)
		}
		copy(item.data, buf[:n])
		if !state.enqueue(item, &b.dropped) {
			b.release(item)
		}
	}
}

func (b *Bind) detachIfCurrent(p *peerConn) {
	b.mu.Lock()
	if b.peers[p.id] == p {
		delete(b.peers, p.id)
		p.active.Store(false)
	}
	b.mu.Unlock()
	_ = p.conn.Close()
}

func (state *runState) enqueue(item queuedPacket, dropped *atomic.Uint64) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || !item.peer.active.Load() {
		return false
	}
	if state.queuedBytes+len(item.data) > maxQueuedBytes {
		dropped.Add(1)
		return false
	}
	select {
	case state.queue <- item:
		state.queuedBytes += len(item.data)
		return true
	default:
		dropped.Add(1)
		return false
	}
}

func (b *Bind) release(item queuedPacket) {
	if item.backing != nil {
		b.pool.Put(item.backing)
	}
}

func (b *Bind) receiveFunc(state *runState) wgconn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, ErrShortBuffer
		}
		for {
			select {
			case <-state.stop:
				return 0, net.ErrClosed
			default:
			}
			var item queuedPacket
			select {
			case <-state.stop:
				return 0, net.ErrClosed
			case item = <-state.queue:
			}
			state.mu.Lock()
			state.queuedBytes -= len(item.data)
			state.mu.Unlock()
			b.mu.Lock()
			valid := b.state == state && b.peers[item.peer.id] == item.peer && item.peer.active.Load()
			if !valid {
				b.mu.Unlock()
				b.release(item)
				continue
			}
			if len(packets[0]) < len(item.data) {
				b.mu.Unlock()
				b.release(item)
				return 0, ErrShortBuffer
			}
			copy(packets[0], item.data)
			sizes[0] = len(item.data)
			eps[0] = item.peer.endpoint
			b.mu.Unlock()
			b.release(item)
			return 1, nil
		}
	}
}

func validPeerID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func makeEndpoint(owner *Bind, peerID string, conn net.Conn) *endpoint {
	e := &endpoint{owner: owner, peerID: peerID}
	e.local = addrPort(conn.LocalAddr())
	e.remote = addrPort(conn.RemoteAddr())
	material := []byte("directlan-ice-endpoint-v1\x00" + peerID + "\x00")
	if e.remote.IsValid() {
		encoded, _ := e.remote.MarshalBinary()
		material = append(material, encoded...)
	}
	e.cookie = sha256.Sum256(material)
	return e
}

func addrPort(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		ap := udp.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port())
}

func (*endpoint) ClearSrc()             {}
func (e *endpoint) SrcToString() string { return e.local.String() }
func (e *endpoint) DstToString() string { return e.peerID }
func (e *endpoint) DstToBytes() []byte  { return e.cookie[:] }
func (e *endpoint) DstIP() netip.Addr   { return e.remote.Addr() }
func (e *endpoint) SrcIP() netip.Addr   { return e.local.Addr() }
