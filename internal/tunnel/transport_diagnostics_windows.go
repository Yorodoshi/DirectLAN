//go:build windows

package tunnel

import (
	"encoding/binary"
	"sync/atomic"
)

// NativeUDPIn/Out and MaskRejected are socket-wide packet counts, including
// STUN/control. Masked wire counts are attributed after envelope authentication.
// Unmasked wire counts are socket-wide (PeerAttributed=false): a raw initiation
// cannot be attributed to a static peer before WireGuard authenticates it.
// These counters never authorize packets or report WireGuard authentication.
type TransportDiagnostics struct {
	NativeUDPIn, NativeUDPOut                 uint64
	MaskAuthenticatedIn, MaskAuthenticatedOut uint64
	MaskRejected                              uint64
	InitiationIn, InitiationOut               uint64
	ResponseIn, ResponseOut                   uint64
	DataIn, DataOut                           uint64
	ControlAuthenticatedIn, ControlSent       uint64
	ControlRejected                           uint64
	PeerAttributed                            bool
}

type wireCounters struct{ initiation, response, data atomic.Uint64 }

func (c *wireCounters) record(packet []byte) {
	if len(packet) < 4 {
		return
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 1:
		c.initiation.Add(1)
	case 2:
		c.response.Add(1)
	case 4:
		c.data.Add(1)
	}
}

type maskedCounters struct {
	in, out         wireCounters
	authIn, authOut atomic.Uint64
}

type transportCounters struct {
	rawIn, rawOut, rejected atomic.Uint64
	in, out                 wireCounters
}

func (m *udpMask) record(id string, packet []byte, incoming bool) {
	m.mu.RLock()
	p := m.peers[id]
	m.mu.RUnlock()
	if p == nil {
		return
	}
	if incoming {
		p.diagnostics.authIn.Add(1)
		p.diagnostics.in.record(packet)
	} else {
		p.diagnostics.authOut.Add(1)
		p.diagnostics.out.record(packet)
	}
}

func (t *Tunnel) TransportDiagnostics(peerID string) (TransportDiagnostics, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running || t.direct == nil {
		return TransportDiagnostics{}, ErrNotStarted
	}
	if t.peers[peerID] == nil {
		if t.control == nil {
			return TransportDiagnostics{}, ErrUnknownPeer
		}
		t.control.mu.RLock()
		known := t.control.peers[peerID] != nil
		t.control.mu.RUnlock()
		if !known {
			return TransportDiagnostics{}, ErrUnknownPeer
		}
	}
	c := &t.direct.transport
	d := TransportDiagnostics{NativeUDPIn: c.rawIn.Load(), NativeUDPOut: c.rawOut.Load(), MaskRejected: c.rejected.Load(), PeerAttributed: t.direct.mask != nil}
	in, out := &c.in, &c.out
	if mask := t.direct.mask; mask != nil {
		mask.mu.RLock()
		p := mask.peers[peerID]
		mask.mu.RUnlock()
		var counters maskedCounters
		current := &counters
		if p != nil {
			current = &p.diagnostics
		}
		in, out = &current.in, &current.out
		d.MaskAuthenticatedIn, d.MaskAuthenticatedOut = current.authIn.Load(), current.authOut.Load()
	}
	d.InitiationIn, d.InitiationOut = in.initiation.Load(), out.initiation.Load()
	d.ResponseIn, d.ResponseOut = in.response.Load(), out.response.Load()
	d.DataIn, d.DataOut = in.data.Load(), out.data.Load()
	if t.control != nil {
		t.control.mu.RLock()
		if p := t.control.peers[peerID]; p != nil {
			d.ControlAuthenticatedIn, d.ControlSent, d.ControlRejected = p.authIn.Load(), p.sent.Load(), p.rejected.Load()
		}
		t.control.mu.RUnlock()
	}
	return d, nil
}
