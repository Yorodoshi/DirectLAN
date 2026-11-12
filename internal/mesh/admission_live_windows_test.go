//go:build windows

package mesh

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

type admissionFixture struct {
	data       map[string]bool
	control    map[string]bool
	failAdd    int
	adds       int
	failRemove bool
}

func (f *admissionFixture) AddSecureDirectPeer(id string, _ []byte, _ net.IP, _ netip.AddrPort) error {
	f.adds++
	if f.failAdd == f.adds {
		return errors.New("route installation failed")
	}
	f.data[id] = true
	return nil
}
func (f *admissionFixture) ConfigureControlPeer(id string, _ []byte, _ netip.AddrPort) error {
	f.control[id] = true
	return nil
}
func (f *admissionFixture) RemovePeer(id string) error {
	delete(f.data, id)
	delete(f.control, id)
	if f.failRemove {
		return errors.New("route cleanup failed")
	}
	return nil
}

func TestAdmissionInstallsSignedPeersWithoutSocketRestart(t *testing.T) {
	next, _ := testNetwork(t)
	old := next
	old.Members = append([]Member(nil), next.Members[:1]...)
	self := next.Members[1]
	for _, failure := range []string{"", "second peer", "save", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			wg := &admissionFixture{data: map[string]bool{}, control: map[string]bool{memberID(old.Members[0]): true}}
			if failure == "second peer" {
				wg.failAdd = 2
			}
			if failure == "rollback" {
				wg.failRemove = true
			}
			saved := false
			err := installAdmission(wg, profile{Pending: true, LocalIP: self.IP}, old, next, self, func() error {
				if failure == "save" || failure == "rollback" {
					return errors.New("disk failure")
				}
				saved = true
				return nil
			})
			if failure == "" {
				if err != nil || !saved || len(wg.data) != len(next.Members)-1 || wg.data[memberID(self)] {
					t.Fatalf("signed admission failed: %v", err)
				}
			} else if err == nil || saved || len(wg.data) != 0 || !wg.control[memberID(old.Members[0])] {
				t.Fatalf("failed admission did not restore isolation: %v", err)
			}
			if errors.Is(err, errAdmissionRollback) != (failure == "rollback") {
				t.Fatalf("rollback status: %v", err)
			}
		})
	}
}
