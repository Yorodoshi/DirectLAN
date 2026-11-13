//go:build windows

package tunnel

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v4"
	"golang.zx2c4.com/wireguard/conn"
)

// stunBind uses the WireGuard socket itself so the server observes the NAT
// mapping of the tunnel, including any port translation.
type stunBind struct {
	conn.Bind
	interfaces DirectInterfaces
	mu         sync.Mutex
	pending    map[[stun.TransactionIDSize]byte]stunQuery
	mask       *udpMask
	control    *controlTransport
	transport  transportCounters
}

type stunQuery struct {
	server netip.AddrPort
	result chan netip.AddrPort
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	receivers, port, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if b.interfaces != (DirectInterfaces{}) {
		sockets, ok := b.Bind.(conn.BindSocketToInterface)
		if !ok {
			_ = b.Close()
			return nil, 0, fmt.Errorf("WireGuard UDP bind cannot select a Windows interface")
		}
		for _, receive := range receivers {
			switch receive.PrettyName() {
			case "v4":
				if b.interfaces.IPv4 != 0 {
					err = sockets.BindSocketToInterface4(b.interfaces.IPv4, false)
				}
			case "v6":
				if b.interfaces.IPv6 != 0 {
					err = sockets.BindSocketToInterface6(b.interfaces.IPv6, false)
				}
			}
			if err != nil {
				_ = b.Close()
				return nil, 0, fmt.Errorf("bind WireGuard UDP to physical interface: %w", err)
			}
		}
	}
	for i, receive := range receivers {
		receivers[i] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			n, err := receive(packets, sizes, endpoints)
			if err != nil {
				return n, err
			}
			for i, size := range sizes[:n] {
				b.transport.rawIn.Add(1)
				packet := packets[i][:size]
				if stun.IsMessage(packet) && packet[0] == 1 && packet[1] == 1 {
					b.receiveSTUN(packet, endpoints[i])
					sizes[i] = 0
				} else if b.control != nil && b.control.receive(packet, endpoints[i]) {
					sizes[i] = 0
				} else if b.mask != nil {
					id, size, err := b.mask.open(packet)
					if err != nil {
						b.transport.rejected.Add(1)
						sizes[i] = 0
						continue
					}
					sizes[i] = size
					b.mask.record(id, packet[:size], true)
					endpoints[i] = &maskedEndpoint{Endpoint: endpoints[i], peerID: id}
				} else {
					b.transport.in.record(packet)
				}
			}
			return n, nil
		}
	}
	return receivers, port, nil
}

func (b *stunBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	if b.mask == nil {
		return b.Bind.ParseEndpoint(text)
	}
	id, address, ok := strings.Cut(text, "@")
	if !ok || !b.mask.has(id) {
		return nil, ErrUnknownPeer
	}
	endpoint, err := b.Bind.ParseEndpoint(address)
	if err != nil {
		return nil, err
	}
	return &maskedEndpoint{Endpoint: endpoint, peerID: id}, nil
}

func (b *stunBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	if b.mask == nil {
		if err := b.Bind.Send(packets, endpoint); err != nil {
			return err
		}
		b.transport.rawOut.Add(uint64(len(packets)))
		for _, packet := range packets {
			b.transport.out.record(packet)
		}
		return nil
	}
	masked, ok := endpoint.(*maskedEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, packet := range packets {
		sealed, err := b.mask.seal(masked.peerID, packet)
		if err != nil {
			return err
		}
		if err := b.Bind.Send([][]byte{sealed}, masked.Endpoint); err != nil {
			return err
		}
		b.transport.rawOut.Add(1)
		b.mask.record(masked.peerID, packet, false)
	}
	return nil
}

func (b *stunBind) receiveSTUN(packet []byte, from conn.Endpoint) {
	id := [stun.TransactionIDSize]byte(packet[8:20])
	b.mu.Lock()
	query, ok := b.pending[id]
	b.mu.Unlock()
	if !ok {
		return
	}
	source, err := netip.ParseAddrPort(from.DstToString())
	if err != nil || source != query.server {
		return
	}
	var message stun.Message
	if err := stun.Decode(packet, &message); err != nil || message.Type != stun.BindingSuccess {
		return
	}
	if message.Contains(stun.AttrFingerprint) && stun.Fingerprint.Check(&message) != nil {
		return
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(&message); err != nil || mapped.Port <= 0 || mapped.Port > 65535 {
		return
	}
	if addr, ok := netip.AddrFromSlice(mapped.IP); ok {
		select {
		case query.result <- netip.AddrPortFrom(addr.Unmap(), uint16(mapped.Port)):
		default:
		}
	}
}

func (b *stunBind) discover(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	endpoint, err := b.Bind.ParseEndpoint(server.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	message, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	query := stunQuery{server: server, result: make(chan netip.AddrPort, 1)}
	b.mu.Lock()
	if b.pending == nil {
		b.pending = make(map[[stun.TransactionIDSize]byte]stunQuery)
	}
	b.pending[message.TransactionID] = query
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, message.TransactionID)
		b.mu.Unlock()
	}()

	resend := time.NewTicker(500 * time.Millisecond)
	defer resend.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return netip.AddrPort{}, err
		}
		if err := b.Bind.Send([][]byte{message.Raw}, endpoint); err != nil {
			return netip.AddrPort{}, err
		}
		b.transport.rawOut.Add(1)
		select {
		case result := <-query.result:
			return result, nil
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-resend.C:
		}
	}
}
