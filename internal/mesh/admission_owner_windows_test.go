//go:build windows

package mesh

import (
	"errors"
	"net/netip"
	"testing"
)

type ownerAdmissionFixture struct {
	admissionFixture
	failControl bool
	removes     []string
}

func (f *ownerAdmissionFixture) ConfigureControlPeer(id string, key []byte, endpoint netip.AddrPort) error {
	if err := f.admissionFixture.ConfigureControlPeer(id, key, endpoint); err != nil {
		return err
	}
	if f.failControl {
		return errors.New("control configuration failed")
	}
	return nil
}

func (f *ownerAdmissionFixture) RemovePeer(id string) error {
	f.removes = append(f.removes, id)
	return f.admissionFixture.RemovePeer(id)
}

func TestOwnerAddsOnlyNewPeerAndPreservesExistingConnections(t *testing.T) {
	code, _ := testNetwork(t)
	oldID, newID := memberID(code.Members[1]), memberID(code.Members[2])
	for _, failure := range []string{"", "add", "control", "save", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			wg := &ownerAdmissionFixture{admissionFixture: admissionFixture{
				data: map[string]bool{oldID: true}, control: map[string]bool{oldID: true}}}
			wg.failControl = failure == "control"
			wg.failRemove = failure == "cleanup"
			if failure == "add" {
				wg.failAdd = 1
			}
			saved := false
			err := installOwnerMember(wg, profile{}, code.Members[2], func() error {
				if !wg.data[oldID] || !wg.control[oldID] || !wg.data[newID] || !wg.control[newID] {
					t.Fatal("save ran before installing the new peer or after disturbing an existing peer")
				}
				if failure == "save" || failure == "cleanup" {
					return errors.New("profile save failed")
				}
				saved = true
				return nil
			})
			if wg.adds != 1 || !wg.data[oldID] || !wg.control[oldID] {
				t.Fatal("adding one member reinstalled or revoked an existing connection")
			}
			if failure == "" {
				if err != nil || !saved || !wg.data[newID] || !wg.control[newID] || len(wg.removes) != 0 {
					t.Fatalf("new owner-approved member was not committed: %v", err)
				}
			} else {
				if err == nil || saved || wg.data[newID] || wg.control[newID] {
					t.Fatalf("failed new-member installation was not revoked: %v", err)
				}
				wantRemoves := 1
				if failure == "add" {
					wantRemoves = 0
				}
				if len(wg.removes) != wantRemoves || wantRemoves == 1 && wg.removes[0] != newID {
					t.Fatal("rollback affected a peer other than the new member")
				}
			}
			if errors.Is(err, errAdmissionRollback) != (failure == "cleanup") {
				t.Fatalf("cleanup failure was not distinguished for fail-closed handling: %v", err)
			}
		})
	}
}
