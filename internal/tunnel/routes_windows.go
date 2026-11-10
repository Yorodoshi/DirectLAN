//go:build windows

package tunnel

import (
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ipHelper                      = windows.NewLazySystemDLL("iphlpapi.dll")
	convertInterfaceLuidToIndex   = ipHelper.NewProc("ConvertInterfaceLuidToIndex")
	initializeUnicastAddressEntry = ipHelper.NewProc("InitializeUnicastIpAddressEntry")
	createUnicastAddressEntry     = ipHelper.NewProc("CreateUnicastIpAddressEntry")
	deleteUnicastAddressEntry     = ipHelper.NewProc("DeleteUnicastIpAddressEntry")
	initializeForwardEntry        = ipHelper.NewProc("InitializeIpForwardEntry")
	createForwardEntry            = ipHelper.NewProc("CreateIpForwardEntry2")
	deleteForwardEntry            = ipHelper.NewProc("DeleteIpForwardEntry2")
	getIPInterfaceEntry           = ipHelper.NewProc("GetIpInterfaceEntry")
	setIPInterfaceEntry           = ipHelper.NewProc("SetIpInterfaceEntry")
)

// ipInterfaceRow matches the Windows MIB_IPINTERFACE_ROW layout.
// In x/sys v0.41.0 the two offload fields are uint32, but Windows uses
// one byte for each. That puts DisableDefaultRoutes at the wrong offset.
type ipInterfaceRow struct {
	Family               uint16
	_                    [6]byte
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	_                    [124]byte // MaxReassemblySize through ZoneIndices
	SitePrefixLength     uint32
	_                    uint32 // Metric
	NlMtu                uint32
	_                    [8]byte // read-only capability flags and ReachableTime
	_                    uint8   // TransmitOffload
	_                    uint8   // ReceiveOffload
	DisableDefaultRoutes uint8
	_                    uint8
}

func interfaceIndex(luid uint64) (uint32, error) {
	if luid == 0 {
		return 0, fmt.Errorf("invalid Wintun LUID")
	}
	var index uint32
	code, _, _ := convertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	runtime.KeepAlive(luid)
	if err := winCode("ConvertInterfaceLuidToIndex", code); err != nil {
		return 0, err
	}
	if index == 0 {
		return 0, fmt.Errorf("Wintun interface has no index")
	}
	return index, nil
}

func addOverlayAddress(luid uint64, ip net.IP) (windows.MibUnicastIpAddressRow, error) {
	var row windows.MibUnicastIpAddressRow
	initializeUnicastAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = luid
	row.OnLinkPrefixLength = 32 // no subnet-wide route
	// Windows 10+ makes the address usable while it checks for duplicates.
	row.DadState = windows.IpDadStatePreferred
	setSockaddr4(unsafe.Pointer(&row.Address), ip)
	code, _, _ := createUnicastAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	runtime.KeepAlive(&row)
	if err := winCode("CreateUnicastIpAddressEntry", code); err != nil {
		return windows.MibUnicastIpAddressRow{}, err
	}
	return row, nil
}

func removeOverlayAddress(row *windows.MibUnicastIpAddressRow) error {
	if row == nil {
		return nil
	}
	code, _, _ := deleteUnicastAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	runtime.KeepAlive(row)
	if code == uintptr(windows.ERROR_NOT_FOUND) || code == uintptr(windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return winCode("DeleteUnicastIpAddressEntry", code)
}

func addPeerRoute(luid uint64, ip net.IP) (windows.MibIpForwardRow2, error) {
	var row windows.MibIpForwardRow2
	initializeForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = luid
	row.DestinationPrefix.PrefixLength = 32
	setSockaddr4(unsafe.Pointer(&row.DestinationPrefix.Prefix), ip)
	setSockaddr4(unsafe.Pointer(&row.NextHop), net.IPv4zero) // on-link Wintun route
	row.SitePrefixLength = 32
	row.Metric = 1
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Loopback = 0
	row.AutoconfigureAddress = 0
	row.Publish = 0
	code, _, _ := createForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	runtime.KeepAlive(&row)
	if err := winCode("CreateIpForwardEntry2", code); err != nil {
		return windows.MibIpForwardRow2{}, err
	}
	return row, nil
}

func removePeerRoute(row *windows.MibIpForwardRow2) error {
	if row == nil {
		return nil
	}
	code, _, _ := deleteForwardEntry.Call(uintptr(unsafe.Pointer(row)))
	runtime.KeepAlive(row)
	if code == uintptr(windows.ERROR_NOT_FOUND) || code == uintptr(windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return winCode("DeleteIpForwardEntry2", code)
}

func setOverlayMTU(luid uint64, mtu uint32) error {
	row := ipInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	code, _, _ := getIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := winCode("GetIpInterfaceEntry", code); err != nil {
		return err
	}
	row.NlMtu = mtu
	row.DisableDefaultRoutes = 1
	// GetIpInterfaceEntry may return a site prefix. SetIpInterfaceEntry
	// requires zero for IPv4, even when changing only the MTU.
	row.SitePrefixLength = 0
	code, _, _ = setIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := winCode("SetIpInterfaceEntry", code); err != nil {
		return err
	}
	check := ipInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	code, _, _ = getIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&check)))
	if err := winCode("verify GetIpInterfaceEntry", code); err != nil {
		return err
	}
	if check.NlMtu != mtu || check.DisableDefaultRoutes != 1 {
		return fmt.Errorf("Wintun interface settings did not persist (MTU %d, disable-default %d)", check.NlMtu, check.DisableDefaultRoutes)
	}
	return nil
}

func setSockaddr4(dst unsafe.Pointer, ip net.IP) {
	addr := (*windows.RawSockaddrInet4)(dst)
	addr.Family = windows.AF_INET
	copy(addr.Addr[:], ip.To4())
}

func winCode(operation string, code uintptr) error {
	if code != 0 {
		return fmt.Errorf("%s: %w", operation, syscall.Errno(code))
	}
	return nil
}
