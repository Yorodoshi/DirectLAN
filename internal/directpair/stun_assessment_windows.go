//go:build windows

package directpair

import (
	"context"
	"net"
	"net/netip"
	"time"

	"directlan/internal/tunnel"
)

// MappingAssessment reports only successful public STUN observations. Matching
// samples do not prove reachability; timeouts do not establish a NAT type.
type MappingAssessment struct {
	Samples  int    `json:"samples"`
	Distinct int    `json:"distinct"`
	Result   string `json:"result"`
}

func discoverSTUNReport(ctx context.Context, wg *tunnel.Tunnel) ([]netip.AddrPort, MappingAssessment) {
	return sampleSTUNMappings(ctx, net.DefaultResolver.LookupNetIP, wg.DiscoverDirectEndpoint)
}

func sampleSTUNMappings(ctx context.Context, lookup func(context.Context, string, string) ([]netip.Addr, error), query func(context.Context, netip.AddrPort) (netip.AddrPort, error)) ([]netip.AddrPort, MappingAssessment) {
	providers := [...]struct {
		host string
		port uint16
	}{
		{"stun.cloudflare.com", 3478},
		{"stun.l.google.com", 19302},
	}
	var observed []netip.AddrPort
	report := MappingAssessment{Result: "no_reply"}
	for _, provider := range providers {
		if ctx.Err() != nil {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
		ips, err := lookup(attempt, "ip4", provider.host)
		var endpoint netip.AddrPort
		if err == nil && attempt.Err() == nil {
			for _, ip := range ips {
				server := netip.AddrPortFrom(ip.Unmap(), provider.port)
				if PublicEndpoint(server) {
					endpoint, err = query(attempt, server)
					break
				}
			}
		}
		if err == nil && attempt.Err() == nil && PublicEndpoint(endpoint) {
			report.Samples++
			duplicate := false
			for _, known := range observed {
				if known == endpoint {
					duplicate = true
					break
				}
			}
			if !duplicate {
				observed = append(observed, endpoint)
			}
		}
		cancel()
	}
	report.Distinct = len(observed)
	switch {
	case report.Distinct > 1:
		report.Result = "different_observations"
	case report.Samples > 1:
		report.Result = "samples_match"
	case report.Samples == 1:
		report.Result = "single_observation"
	}
	return observed, report
}
