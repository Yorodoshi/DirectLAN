//go:build windows

package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNativeUDPRespondsToObservedGuestDespiteStaleConfiguredEndpoint(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(fmt.Sprint("masked=", masked), func(t *testing.T) {
			ownerKey, guestKey, _, _ := cryptoPair(t, "diagnostics-test")
			ownerIP, guestIP := net.ParseIP("10.233.75.1").To4(), net.ParseIP("10.233.75.2").To4()
			owner, ownerTUN, ownerPort := diagnosticWG(t, ownerKey, ownerIP, masked)
			guest, guestTUN, guestPort := diagnosticWG(t, guestKey, guestIP, masked)
			// Reserve a live but unrelated endpoint. The owner cannot initiate
			// successfully until it learns the guest from the incoming handshake.
			stale, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer stale.Close()
			diagnosticPeer(t, owner, guestKey, guestIP, stale.LocalAddr().(*net.UDPAddr).AddrPort())
			diagnosticPeer(t, guest, ownerKey, ownerIP, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ownerPort))
			payload := append([]byte(probePrefix), bytes.Repeat([]byte{0xa6}, 32)...)
			request := diagnosticPacket(guestIP, ownerIP, 52001, ProbePort, payload)
			guestTUN.outgoing <- request
			select {
			case got := <-ownerTUN.incoming:
				if !bytes.Equal(got, request) {
					t.Fatal("guest packet changed after roaming")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("owner did not answer the guest's observed source")
			}
			stats, err := owner.Stats("peer")
			want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), guestPort).String()
			if err != nil || stats.Endpoint != want {
				t.Fatalf("owner did not replace stale endpoint with observed guest: %v", err)
			}
			reply := diagnosticPacket(ownerIP, guestIP, ProbePort, 52001, payload)
			ownerTUN.outgoing <- reply
			select {
			case got := <-guestTUN.incoming:
				if !bytes.Equal(got, reply) {
					t.Fatal("owner packet changed after roaming")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("owner data did not reach guest after roaming")
			}
			for _, node := range []*Tunnel{owner, guest} {
				d, err := node.TransportDiagnostics("peer")
				if err != nil || d.NativeUDPIn == 0 || d.NativeUDPOut == 0 || d.DataIn == 0 || d.DataOut == 0 || d.PeerAttributed != masked {
					t.Fatalf("native UDP counters did not observe the roaming data exchange: %+v, %v", d, err)
				}
				if masked && (d.MaskAuthenticatedIn == 0 || d.MaskAuthenticatedOut == 0 || d.MaskRejected != 0) {
					t.Fatalf("masked counters did not observe authenticated envelopes: %+v", d)
				}
			}
			d, _ := owner.TransportDiagnostics("peer")
			if d.InitiationIn == 0 || d.ResponseOut == 0 {
				t.Fatalf("response after roaming was not recorded: %+v", d)
			}
			d, _ = guest.TransportDiagnostics("peer")
			if d.InitiationOut == 0 || d.ResponseIn == 0 {
				t.Fatalf("guest did not receive the roaming response: %+v", d)
			}
			if masked {
				before, _ := owner.TransportDiagnostics("peer")
				packet, err := guest.direct.mask.seal("peer", []byte{4, 0, 0, 0})
				if err != nil {
					t.Fatal(err)
				}
				packet[len(packet)-1] ^= 1
				endpoint, err := guest.direct.Bind.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ownerPort).String())
				if err != nil {
					t.Fatal(err)
				}
				if err := guest.direct.Bind.Send([][]byte{packet}, endpoint); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(time.Second)
				for {
					after, _ := owner.TransportDiagnostics("peer")
					if after.MaskRejected > before.MaskRejected {
						if after.NativeUDPIn <= before.NativeUDPIn || after.MaskAuthenticatedIn != before.MaskAuthenticatedIn || after.DataIn != before.DataIn {
							t.Fatal("corrupted native UDP was counted as an authenticated masked packet")
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("corrupted envelope was not counted as rejected")
					}
					time.Sleep(time.Millisecond)
				}
			}
		})
	}
}
