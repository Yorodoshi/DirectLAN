//go:build windows

package tunnel

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

type packetPolicy struct {
	mu      sync.RWMutex
	local   [4]byte
	peers   map[[4]byte]bool
	dropped atomic.Uint64
}

func newPolicy(local net.IP) *packetPolicy {
	p := &packetPolicy{peers: make(map[[4]byte]bool)}
	copy(p.local[:], local.To4())
	return p
}
func (p *packetPolicy) setPeer(ip net.IP, allowed bool) {
	var key [4]byte
	copy(key[:], ip.To4())
	p.mu.Lock()
	defer p.mu.Unlock()
	if allowed {
		p.peers[key] = true
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
	allowed := source == p.local && p.peers[dest]
	if incoming {
		allowed = dest == p.local && p.peers[source]
	}
	if !allowed {
		p.dropped.Add(1)
	}
	return allowed
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
			if _, err := p.Device.Write([][]byte{b}, offset); err != nil {
				return i, err
			}
		}
	}
	return len(buffers), nil
}
