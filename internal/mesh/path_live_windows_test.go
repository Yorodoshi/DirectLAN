//go:build windows

package mesh

import (
	"net/netip"
	"os"
	"strconv"
	"testing"
)

func TestPhysicalCaptureLive(t *testing.T) {
	if os.Getenv("DIRECTLAN_TEST_PHYSICAL_LOCAL") == "" {
		t.Skip("requires administrator and an active IPv4 UDP peer")
	}
	local := netip.MustParseAddr(os.Getenv("DIRECTLAN_TEST_PHYSICAL_LOCAL"))
	peer := netip.MustParseAddr(os.Getenv("DIRECTLAN_TEST_PHYSICAL_PEER"))
	port, err := strconv.ParseUint(os.Getenv("DIRECTLAN_TEST_PHYSICAL_PORT"), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	tx, rx, err := countPhysical(local, uint16(port), map[netip.Addr]bool{peer: true})
	if err != nil || tx+rx == 0 {
		t.Fatalf("sent=%d received=%d err=%v", tx, rx, err)
	}
}
