//go:build windows

package directpair

import (
	"net/netip"

	"directlan/internal/platform"
	"directlan/internal/tunnel"
)

func physicalInterfaces() (tunnel.DirectInterfaces, string) {
	adapters, _ := platform.PhysicalCandidates()
	var v4, v6 platform.Adapter
	for _, adapter := range adapters {
		if !adapter.IsHardware() {
			continue
		}
		for _, raw := range adapter.Gateways {
			gateway, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			if gateway.Is4() && adapter.Index != 0 && (v4.Index == 0 || adapter.IPv4Metric < v4.IPv4Metric) {
				v4 = adapter
			}
			if gateway.Is6() && adapter.IPv6Index != 0 && (v6.IPv6Index == 0 || adapter.IPv6Metric < v6.IPv6Metric) {
				v6 = adapter
			}
		}
	}
	name := v4.Name
	if name == "" {
		name = v6.Name
	} else if v6.Name != "" && v6.Name != name {
		name += " / " + v6.Name
	}
	return tunnel.DirectInterfaces{IPv4: v4.Index, IPv6: v6.IPv6Index}, name
}
