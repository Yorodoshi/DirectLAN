//go:build windows

package mesh

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type updatedPeer struct {
	key []byte
	ip  net.IP
}

type updateFixture struct {
	data                                   map[string]*updatedPeer
	control                                map[string][]byte
	adds, removes, configures              int
	failAddAt, failRemoveAt, failControlAt int
}

func (f *updateFixture) AddSecureDirectPeer(id string, key []byte, ip net.IP, _ netip.AddrPort) error {
	f.adds++
	if f.adds == f.failAddAt {
		return errors.New("add failure")
	}
	if f.data[id] != nil {
		return errors.New("duplicate data peer")
	}
	f.data[id] = &updatedPeer{append([]byte(nil), key...), append(net.IP(nil), ip...)}
	return nil
}
func (f *updateFixture) ConfigureControlPeer(id string, key []byte, _ netip.AddrPort) error {
	f.configures++
	f.control[id] = append([]byte(nil), key...)
	if f.configures == f.failControlAt {
		return errors.New("control failure")
	}
	return nil
}
func (f *updateFixture) RemovePeer(id string) error {
	f.removes++
	delete(f.data, id)
	delete(f.control, id)
	if f.removes == f.failRemoveAt {
		return errors.New("remove failure")
	}
	return nil
}
func updateRuntime(code Code, self Member) *updateFixture {
	f := &updateFixture{data: make(map[string]*updatedPeer), control: make(map[string][]byte)}
	for _, member := range code.Members {
		if bytes.Equal(member.Identity, self.Identity) {
			continue
		}
		id := memberID(member)
		f.data[id] = &updatedPeer{member.WireGuard, member.IP.AsSlice()}
		if memberNeedsControl(code, self, member) {
			f.control[id] = member.WireGuard
		}
	}
	return f
}
func assertRuntimeRoster(t *testing.T, f *updateFixture, code Code, self Member) {
	t.Helper()
	if len(f.data) != len(code.Members)-1 {
		t.Fatalf("wrong peer count: %d", len(f.data))
	}
	controls := 0
	for _, member := range code.Members {
		if bytes.Equal(member.Identity, self.Identity) {
			continue
		}
		id := memberID(member)
		p := f.data[id]
		if p == nil || !bytes.Equal(p.key, member.WireGuard) || !p.ip.Equal(member.IP.AsSlice()) {
			t.Fatal("runtime does not match signed peer authorization")
		}
		if memberNeedsControl(code, self, member) {
			controls++
			if !bytes.Equal(f.control[id], member.WireGuard) {
				t.Fatal("control peer key was not restored or installed")
			}
		}
	}
	if len(f.control) != controls {
		t.Fatal("non-owner guest gained a control authorization")
	}
}

func TestRosterUpdatePreservesUnchangedSessionsAndRevokesChangedAuthorization(t *testing.T) {
	for _, role := range []int{0, 1} {
		for _, operation := range []string{"add", "remove", "key_and_ip", "owner_key"} {
			t.Run(string(rune('A'+role))+"/"+operation, func(t *testing.T) {
				old, _ := testNetwork(t)
				self := old.Members[role]
				next := old
				next.Members = append([]Member(nil), old.Members...)
				next.Revision++
				switch operation {
				case "add":
					member, _ := testMember(t, "Fourth", "10.213.47.4")
					next.Members = append(next.Members, member)
				case "remove":
					next.Members = next.Members[:2]
				case "key_and_ip":
					member, _ := testMember(t, "Replacement", "10.213.47.5")
					next.Members[2].WireGuard, next.Members[2].IP = member.WireGuard, member.IP
				case "owner_key":
					if role == 0 {
						return
					}
					member, _ := testMember(t, "New owner key", "10.213.47.1")
					next.Members[0].WireGuard = member.WireGuard
				}
				f := updateRuntime(old, self)
				unchanged := make(map[string]*updatedPeer)
				for _, member := range next.Members {
					if known, ok := localMember(old, member.Identity); ok && sameMemberAuthorization(known, member) {
						unchanged[memberID(member)] = f.data[memberID(member)]
					}
				}
				saved := false
				if err := installRosterUpdate(f, profile{LocalIP: self.IP}, old, next, self, func() error {
					assertRuntimeRoster(t, f, next, self)
					saved = true
					return nil
				}); err != nil || !saved {
					t.Fatalf("incremental roster failed: %v", err)
				}
				for id, object := range unchanged {
					if f.data[id] != object {
						t.Fatal("unchanged peer session was replaced")
					}
				}
			})
		}
	}
}

func TestRosterUpdateRollsBackPartialChangesOrRequiresFailClosedStop(t *testing.T) {
	for _, failure := range []string{"add", "control", "save", "remove", "rollback_remove"} {
		t.Run(failure, func(t *testing.T) {
			old, _ := testNetwork(t)
			self := old.Members[1]
			next := old
			next.Members = append([]Member(nil), old.Members[:2]...)
			next.Revision++
			member, _ := testMember(t, "Fourth", "10.213.47.4")
			next.Members = append(next.Members, member)
			if failure == "control" {
				newer, _ := testMember(t, "New key", "10.213.47.1")
				next.Members[0].WireGuard = newer.WireGuard
			}
			f := updateRuntime(old, self)
			owner := f.data[memberID(old.Members[0])]
			switch failure {
			case "add":
				f.failAddAt = 1
			case "control":
				f.failControlAt = 1
			case "remove":
				f.failRemoveAt = 1
			case "rollback_remove":
				f.failRemoveAt = 2
			}
			err := installRosterUpdate(f, profile{LocalIP: self.IP}, old, next, self, func() error { return errors.New("save failure") })
			if err == nil || !errors.Is(err, errAdmissionRollback) {
				t.Fatalf("wrong rollback status: %v", err)
			}
			if f.data[memberID(old.Members[2])] != nil {
				t.Fatal("failed revocation update restored the revoked key")
			}
			if failure != "control" && f.data[memberID(old.Members[0])] != owner {
				t.Fatal("rollback touched an unchanged owner session")
			}
		})
	}
}

func TestRosterAdditionFailurePreservesExistingNetwork(t *testing.T) {
	for _, failure := range []string{"add", "save", "rollback_remove"} {
		t.Run(failure, func(t *testing.T) {
			old, _ := testNetwork(t)
			self := old.Members[1]
			next := old
			member, _ := testMember(t, "Fourth", "10.213.47.4")
			next.Members = append(append([]Member(nil), old.Members...), member)
			next.Revision++
			f := updateRuntime(old, self)
			if failure == "add" {
				f.failAddAt = 1
			}
			if failure == "rollback_remove" {
				f.failRemoveAt = 1
			}
			err := installRosterUpdate(f, profile{LocalIP: self.IP}, old, next, self, func() error { return errors.New("save failure") })
			if err == nil || errors.Is(err, errAdmissionRollback) != (failure == "rollback_remove") {
				t.Fatalf("wrong addition rollback result: %v", err)
			}
			assertRuntimeRoster(t, f, old, self)
		})
	}
}

func TestRosterUpdateRejectsLocalAuthorizationChangeBeforeMutatingRuntime(t *testing.T) {
	old, _ := testNetwork(t)
	self := old.Members[1]
	next := old
	next.Members = append([]Member(nil), old.Members...)
	next.Members[1].IP = netip.MustParseAddr("10.213.47.20")
	f := updateRuntime(old, self)
	if err := installRosterUpdate(f, profile{}, old, next, self, func() error { t.Fatal("invalid update was saved"); return nil }); err == nil {
		t.Fatal("local IP change used membership-only update")
	}
	if f.adds != 0 || f.removes != 0 || f.configures != 0 {
		t.Fatal("invalid update mutated the live runtime")
	}
}
