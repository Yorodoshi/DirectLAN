//go:build windows

package tunnel

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type packetPolicy struct {
	mu                sync.RWMutex
	local             [4]byte
	peers             map[[4]byte]*packetCounters
	dropped           atomic.Uint64
	echoReadErrors    atomic.Uint64
	lastEchoReadError atomic.Pointer[writeFailure]
}

type writeFailure struct {
	message string
	at      time.Time
}

type packetCounters struct {
	outbound, inbound          atomic.Uint64
	droppedOutbound, droppedIn atomic.Uint64
	echoRequests, echoReplies  atomic.Uint64
	writeErrors                atomic.Uint64
	lastWriteError             atomic.Pointer[writeFailure]
}

// PeerDiagnostics observes the local path. InboundPackets means authenticated
// IP packets accepted before writing to Wintun, not confirmed socket delivery.
// PolicyDrops includes packets that cannot be attributed to an approved peer.
type PeerDiagnostics struct {
	OutboundPackets     uint64    `json:"outbound_packets"`
	InboundPackets      uint64    `json:"inbound_packets"`
	OutboundDrops       uint64    `json:"outbound_drops"`
	InboundDrops        uint64    `json:"inbound_drops"`
	PolicyDrops         uint64    `json:"policy_drops"`
	EchoRequests        uint64    `json:"echo_requests"`
	EchoReplies         uint64    `json:"echo_replies"`
	WriteErrors         uint64    `json:"write_errors"`
	LastWriteError      string    `json:"last_write_error,omitempty"`
	LastWriteErrorAt    time.Time `json:"last_write_error_at,omitzero"`
	EchoReadErrors      uint64    `json:"echo_read_errors"`
	LastEchoReadError   string    `json:"last_echo_read_error,omitempty"`
	LastEchoReadErrorAt time.Time `json:"last_echo_read_error_at,omitzero"`
}

func newPolicy(local net.IP) *packetPolicy {
	p := &packetPolicy{peers: make(map[[4]byte]*packetCounters)}
	copy(p.local[:], local.To4())
	return p
}
func (p *packetPolicy) setPeer(ip net.IP, allowed bool) {
	var key [4]byte
	copy(key[:], ip.To4())
	p.mu.Lock()
	defer p.mu.Unlock()
	if allowed {
		if p.peers[key] == nil {
			p.peers[key] = &packetCounters{}
		}
	} else {
		delete(p.peers, key)
	}
}
func (p *packetPolicy) allows(packet []byte, incoming bool) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		p.dropped.Add(1)
		return false
	}
	header := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || total < header || total > len(packet) {
		p.dropped.Add(1)
		return false
	}
	var source, dest [4]byte
	copy(source[:], packet[12:16])
	copy(dest[:], packet[16:20])
	p.mu.RLock()
	defer p.mu.RUnlock()
	counters := p.peers[dest]
	allowed := source == p.local && counters != nil
	if incoming {
		counters = p.peers[source]
		allowed = dest == p.local && counters != nil
	}
	if !allowed {
		p.dropped.Add(1)
		if counters != nil {
			if incoming {
				counters.droppedIn.Add(1)
			} else {
				counters.droppedOutbound.Add(1)
			}
		}
	} else if incoming {
		counters.inbound.Add(1)
	} else {
		counters.outbound.Add(1)
	}
	return allowed
}

func (p *packetPolicy) counters(ip net.IP) *packetCounters {
	var key [4]byte
	copy(key[:], ip.To4())
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.peers[key]
}

func (p *packetPolicy) diagnostics(ip net.IP) PeerDiagnostics {
	d := PeerDiagnostics{PolicyDrops: p.dropped.Load()}
	d.EchoReadErrors = p.echoReadErrors.Load()
	if failure := p.lastEchoReadError.Load(); failure != nil {
		d.LastEchoReadError, d.LastEchoReadErrorAt = failure.message, failure.at
	}
	if c := p.counters(ip); c != nil {
		d.OutboundPackets, d.InboundPackets = c.outbound.Load(), c.inbound.Load()
		d.OutboundDrops, d.InboundDrops = c.droppedOutbound.Load(), c.droppedIn.Load()
		d.EchoRequests, d.EchoReplies = c.echoRequests.Load(), c.echoReplies.Load()
		d.WriteErrors = c.writeErrors.Load()
		if failure := c.lastWriteError.Load(); failure != nil {
			d.LastWriteError, d.LastWriteErrorAt = failure.message, failure.at
		}
	}
	return d
}

func (p *packetPolicy) recordEcho(ip net.IP, replied bool) {
	if c := p.counters(ip); c != nil {
		c.echoRequests.Add(1)
		if replied {
			c.echoReplies.Add(1)
		}
	}
}

func (p *packetPolicy) recordEchoReadError(err error) {
	p.echoReadErrors.Add(1)
	p.lastEchoReadError.Store(&writeFailure{message: err.Error(), at: time.Now()})
}

func (p *packetPolicy) recordWriteError(packet []byte, err error) {
	if len(packet) >= 20 {
		if c := p.counters(net.IP(packet[12:16])); c != nil {
			c.writeErrors.Add(1)
			c.lastWriteError.Store(&writeFailure{message: err.Error(), at: time.Now()})
		}
	}
}

// Diagnostics returns counters for one authorized peer without changing routes,
// keys or adapter state. Counters remain readable after the tunnel stops.
func (t *Tunnel) Diagnostics(peerID string) (PeerDiagnostics, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	peer := t.peers[peerID]
	if peer == nil || t.policy == nil {
		return PeerDiagnostics{}, ErrUnknownPeer
	}
	return t.policy.diagnostics(peer.ip), nil
}

// policyTUN excludes transit, source spoofing, IPv6 and non-member targets.
// WireGuard additionally enforces the inner source address for each peer key.
type policyTUN struct {
	tun.Device
	policy *packetPolicy
}

func (p *policyTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := p.Device.Read(buffers, sizes, offset)
		if err != nil {
			return n, err
		}
		valid := false
		for i := 0; i < n; i++ {
			if sizes[i] > 0 && offset+sizes[i] <= len(buffers[i]) && p.policy.allows(buffers[i][offset:offset+sizes[i]], false) {
				valid = true
			} else {
				sizes[i] = 0
			}
		}
		if valid {
			return n, nil
		}
	}
}
func (p *policyTUN) Write(buffers [][]byte, offset int) (int, error) {
	for i, b := range buffers {
		if offset <= len(b) && p.policy.allows(b[offset:], true) {
			n, err := p.Device.Write([][]byte{b}, offset)
			if err == nil && n != 1 {
				err = io.ErrShortWrite
			}
			if err != nil {
				p.policy.recordWriteError(b[offset:], err)
				return i, err
			}
		}
	}
	return len(buffers), nil
}
