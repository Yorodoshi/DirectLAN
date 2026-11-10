package directpair

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

const mappingLifetime = 120

type mapping struct {
	endpoint netip.AddrPort
	lifetime time.Duration
}

// PCP and NAT-PMP requests go only to the existing local gateway. No Internet
// address discovery service is involved. Finite leases expire after shutdown.
func requestMapping(ctx context.Context, local, gateway netip.Addr, port uint16, nonce [12]byte, previous netip.AddrPort) (mapping, error) {
	if !local.Is4() || !gateway.Is4() || port == 0 {
		return mapping{}, errors.New("IPv4 gateway required")
	}
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: local.AsSlice()}}
	conn, err := dialer.DialContext(ctx, "udp4", netip.AddrPortFrom(gateway, 5351).String())
	if err != nil {
		return mapping{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	transact := func(packet []byte, opcode byte, minLen int) ([]byte, error) {
		for _, delay := range []time.Duration{300 * time.Millisecond, 600 * time.Millisecond} {
			if err := conn.SetDeadline(time.Now().Add(delay)); err != nil {
				return nil, err
			}
			if _, err := conn.Write(packet); err != nil {
				return nil, err
			}
			var response [1100]byte
			n, err := conn.Read(response[:])
			if err == nil && n >= minLen && response[0] == packet[0] && response[1] == opcode {
				return response[:n], nil
			}
		}
		return nil, errors.New("gateway did not answer the port mapping request")
	}
	pcp := make([]byte, 60)
	pcp[0], pcp[1], pcp[36] = 2, 1, 17 // PCP MAP, UDP
	binary.BigEndian.PutUint32(pcp[4:8], mappingLifetime)
	local16 := local.As16()
	copy(pcp[8:24], local16[:])
	copy(pcp[24:36], nonce[:])
	binary.BigEndian.PutUint16(pcp[40:42], port)
	// The IPv4 wildcard is IPv4-mapped 0.0.0.0, not the IPv6 wildcard.
	pcp[54], pcp[55] = 0xff, 0xff
	if previous.IsValid() && previous.Addr().Is4() {
		binary.BigEndian.PutUint16(pcp[42:44], previous.Port())
	}
	if b, err := transact(pcp, 129, 60); err == nil && b[3] == 0 && b[36] == 17 && bytes.Equal(b[24:36], nonce[:]) && binary.BigEndian.Uint16(b[40:42]) == port {
		return mapping{netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[44:60])).Unmap(), binary.BigEndian.Uint16(b[42:44])), time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Second}, nil
	}
	address, err := transact([]byte{0, 0}, 128, 12)
	if err != nil || binary.BigEndian.Uint16(address[2:4]) != 0 {
		return mapping{}, errors.New("router does not provide PCP or NAT-PMP")
	}
	request := make([]byte, 12)
	request[1] = 1 // NAT-PMP UDP
	binary.BigEndian.PutUint16(request[4:6], port)
	binary.BigEndian.PutUint16(request[6:8], previous.Port())
	binary.BigEndian.PutUint32(request[8:12], mappingLifetime)
	response, err := transact(request, 129, 16)
	if err != nil || binary.BigEndian.Uint16(response[2:4]) != 0 || binary.BigEndian.Uint16(response[8:10]) != port {
		return mapping{}, errors.New("router refused the UDP mapping")
	}
	return mapping{netip.AddrPortFrom(netip.AddrFrom4([4]byte(address[8:12])), binary.BigEndian.Uint16(response[10:12])), time.Duration(binary.BigEndian.Uint32(response[12:16])) * time.Second}, nil
}
