//go:build windows

package tunnel

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestIPInterfaceRowMatchesWindows(t *testing.T) {
	row := ipInterfaceRow{}
	if size, offset := unsafe.Sizeof(row), unsafe.Offsetof(row.DisableDefaultRoutes); size != 168 || offset != 166 {
		t.Fatalf("MIB_IPINTERFACE_ROW size = %d, DisableDefaultRoutes offset = %d", size, offset)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		row.Family = windows.AF_INET
		row.InterfaceIndex = uint32(iface.Index)
		row.DisableDefaultRoutes = 0xff
		code, _, _ := getIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
		if err := winCode("GetIpInterfaceEntry", code); err != nil {
			t.Fatal(err)
		}
		if row.NlMtu == 0 || row.DisableDefaultRoutes > 1 {
			t.Fatalf("Windows returned MTU %d and DisableDefaultRoutes %d", row.NlMtu, row.DisableDefaultRoutes)
		}
		return
	}
	t.Fatal("no loopback interface")
}
