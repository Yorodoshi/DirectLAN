// Package httpsrelay preserves WireGuard datagrams inside standard WebSocket
// binary messages. TLS is provided by HTTPS. Padding changes message lengths;
// it is framing and is not a new encryption algorithm.
package httpsrelay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const MaxFrame = 4096
const MaxDatagram = 2048

type Conn struct {
	ws                          *websocket.Conn
	ctx                         context.Context
	cancel                      context.CancelFunc
	padding                     bool
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
}

func New(ws *websocket.Conn, padding bool) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	ws.SetReadLimit(MaxFrame)
	return &Conn{ws: ws, ctx: ctx, cancel: cancel, padding: padding}
}

func encode(data []byte, padding bool) ([]byte, error) {
	if len(data) == 0 || len(data) > MaxDatagram {
		return nil, errors.New("invalid relay datagram size")
	}
	size := 2 + len(data)
	if padding {
		var choice [1]byte
		if _, err := rand.Read(choice[:]); err != nil {
			return nil, err
		}
		size = ((size+255)/256 + int(choice[0]&1)) * 256
	}
	frame := make([]byte, size)
	binary.BigEndian.PutUint16(frame, uint16(len(data)))
	copy(frame[2:], data)
	if padding {
		if _, err := rand.Read(frame[2+len(data):]); err != nil {
			return nil, err
		}
	}
	return frame, nil
}

func decode(frame []byte) ([]byte, error) {
	if len(frame) < 3 || len(frame) > MaxFrame {
		return nil, errors.New("invalid relay frame")
	}
	n := int(binary.BigEndian.Uint16(frame))
	if n == 0 || n > MaxDatagram || n > len(frame)-2 {
		return nil, errors.New("invalid relay datagram length")
	}
	return frame[2 : 2+n], nil
}

func deadlineContext(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return context.WithCancel(parent)
	}
	return context.WithDeadline(parent, deadline)
}

func (c *Conn) Read(buffer []byte) (int, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	ctx, cancel := deadlineContext(c.ctx, deadline)
	defer cancel()
	typ, frame, err := c.ws.Read(ctx)
	if err != nil {
		return 0, err
	}
	if typ != websocket.MessageBinary {
		return 0, errors.New("relay accepts only binary datagrams")
	}
	data, err := decode(frame)
	if err != nil {
		return 0, err
	}
	if len(buffer) < len(data) {
		return 0, io.ErrShortBuffer
	}
	return copy(buffer, data), nil
}

func (c *Conn) Write(data []byte) (int, error) {
	frame, err := encode(data, c.padding)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if deadline.IsZero() {
		deadline = time.Now().Add(5 * time.Second)
	}
	ctx, cancel := deadlineContext(c.ctx, deadline)
	defer cancel()
	if err := c.ws.Write(ctx, websocket.MessageBinary, frame); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *Conn) Close() error       { c.cancel(); return c.ws.CloseNow() }
func (*Conn) LocalAddr() net.Addr  { return relayAddr("local") }
func (*Conn) RemoteAddr() net.Addr { return relayAddr("https-relay") }
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

type relayAddr string

func (relayAddr) Network() string  { return "wss" }
func (a relayAddr) String() string { return string(a) }
