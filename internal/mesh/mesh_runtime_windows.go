//go:build windows

package mesh

import (
	"context"
	"net"
	"net/netip"

	"directlan/internal/tunnel"
)

// The membership/control state machine owns a running transport, independently
// of Wintun creation. This also permits exercising complete multi-node service
// exchanges without modifying the host's real routes or adapters.
type meshTunnel interface {
	admissionTunnel
	Stop() error
	ReaddressPending(net.IP) error
	DirectPort() (uint16, error)
	DiscoverDirectEndpoint(context.Context, netip.AddrPort) (netip.AddrPort, error)
	SetDirectEndpoint(string, netip.AddrPort) error
	SendControl(string, []byte) error
	ControlMessages() <-chan tunnel.ControlMessage
	Stats(string) (tunnel.PeerStats, error)
	Probe(string) (tunnel.ProbeResult, error)
	Diagnostics(string) (tunnel.PeerDiagnostics, error)
	TransportDiagnostics(string) (tunnel.TransportDiagnostics, error)
}

var _ meshTunnel = (*tunnel.Tunnel)(nil)
