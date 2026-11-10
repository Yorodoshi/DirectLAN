//go:build windows

package platform

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Adapter struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Index      uint32   `json:"index"`
	IPv6Index  uint32   `json:"-"`
	IPv4Metric uint32   `json:"-"`
	IPv6Metric uint32   `json:"-"`
	Kind       string   `json:"kind"`
	Addresses  []string `json:"addresses"`
	Gateways   []string `json:"gateways"`
}

func (a Adapter) IsHardware() bool {
	index := a.Index
	if index == 0 {
		index = a.IPv6Index
	}
	row := windows.MibIfRow2{InterfaceIndex: index}
	return windows.GetIfEntry2Ex(2, &row) == nil && row.InterfaceAndOperStatusFlags&1 != 0
}

// PhysicalCandidates returns active Ethernet and Wi-Fi interfaces that have
// a gateway. They are only candidates; actual egress still needs verification.
func PhysicalCandidates() ([]Adapter, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 * 1024)
	for attempts := 0; attempts < 4; attempts++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		var result []Adapter
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.FirstGatewayAddress == nil {
				continue
			}
			kind := ""
			switch a.IfType {
			case windows.IF_TYPE_ETHERNET_CSMACD:
				kind = "Ethernet"
			case windows.IF_TYPE_IEEE80211:
				kind = "Wi-Fi"
			default:
				continue
			}
			item := Adapter{
				ID: fmt.Sprintf("%d", a.IfIndex), Name: windows.UTF16PtrToString(a.FriendlyName),
				Index: a.IfIndex, IPv6Index: a.Ipv6IfIndex, IPv4Metric: a.Ipv4Metric, IPv6Metric: a.Ipv6Metric, Kind: kind,
			}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				if ip := u.Address.IP(); ip != nil && !ip.IsLoopback() {
					item.Addresses = append(item.Addresses, ip.String())
				}
			}
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				if ip := g.Address.IP(); ip != nil && !ip.IsUnspecified() {
					item.Gateways = append(item.Gateways, ip.String())
				}
			}
			if len(item.Addresses) != 0 && len(item.Gateways) != 0 {
				result = append(result, item)
			}
		}
		return result, nil
	}
	return nil, errors.New("adapter list changed repeatedly")
}

// RouteConflict checks for an existing non-default IPv4 route that overlaps
// the requested overlay prefix. Call it again after network changes.
func RouteConflict(requested *net.IPNet, ownInterfaceIndex uint32) (bool, string, error) {
	if requested == nil || requested.IP.To4() == nil {
		return false, "", errors.New("IPv4 prefix required")
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return false, "", err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range table.Rows() {
		// /0 and the two /1 routes used by full-tunnel VPNs are default
		// transport capture, not evidence that a private address pool is used.
		if row.InterfaceIndex == ownInterfaceIndex || row.DestinationPrefix.PrefixLength <= 1 || row.DestinationPrefix.Prefix.Family != windows.AF_INET {
			continue
		}
		ip := net.IP((*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix)).Addr[:])
		mask := net.CIDRMask(int(row.DestinationPrefix.PrefixLength), 32)
		other := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
		if requested.Contains(other.IP) || other.Contains(requested.IP) {
			return true, other.String(), nil
		}
	}
	return false, "", nil
}
