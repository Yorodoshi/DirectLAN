//go:build windows

package tunnel

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestPacketPolicyStopsTransitAndSpoofing(t *testing.T) {
	p := newPolicy(net.ParseIP("10.221.3.1"))
	p.setPeer(net.ParseIP("10.221.3.2"), true)
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	copy(packet[12:16], net.ParseIP("10.221.3.2").To4())
	copy(packet[16:20], net.ParseIP("10.221.3.1").To4())
	if !p.allows(packet, true) {
		t.Fatal("approved input blocked")
	}
	copy(packet[16:20], net.ParseIP("192.168.1.1").To4())
	if p.allows(packet, true) {
		t.Fatal("transit accepted")
	}
	copy(packet[12:16], net.ParseIP("10.221.3.1").To4())
	copy(packet[16:20], net.ParseIP("10.221.3.2").To4())
	if !p.allows(packet, false) {
		t.Fatal("approved output blocked")
	}
	copy(packet[12:16], net.ParseIP("192.168.1.1").To4())
	if p.allows(packet, false) {
		t.Fatal("spoofed output accepted")
	}
	p.setPeer(net.ParseIP("10.221.3.2"), false)
	copy(packet[12:16], net.ParseIP("10.221.3.1").To4())
	if p.allows(packet, false) {
		t.Fatal("revoked destination accepted")
	}
}
