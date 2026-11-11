//go:build windows

package mesh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"directlan/internal/identity"
)

func pendingAdmissionNode(t *testing.T) (*node, Code, ed25519.PrivateKey) {
	t.Helper()
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, ownerKey := testNetwork(t)
	code.Members = code.Members[:1]
	text, err := Encode(code, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{keys: keys, roster: code, path: filepath.Join(t.TempDir(), "pending.mesh.json"), wake: make(chan struct{}, 1),
		p: profile{Code: text, Name: "Guest", LocalIP: netip.MustParseAddr("10.213.47.2"), Pending: true, Paused: true}}
	if err := n.save(n.p); err != nil {
		t.Fatal(err)
	}
	public, err := keys.WireGuardPublic()
	if err != nil {
		t.Fatal(err)
	}
	admitted := code
	admitted.Revision++
	admitted.Members = append(append([]Member(nil), code.Members...), Member{Identity: keys.IdentityPublic(), WireGuard: public,
		Name: "Guest", IP: netip.MustParseAddr("10.213.47.3")})
	return n, admitted, ownerKey
}

func TestControlRosterAutomaticallyCompletesSignedAdmission(t *testing.T) {
	n, admitted, ownerKey := pendingAdmissionNode(t)
	text, err := Encode(admitted, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.applyControlRoster(text, admitted.Revision); err != nil {
		t.Fatal(err)
	}
	if n.p.Pending || n.p.Code != text || n.p.LocalIP != admitted.Members[1].IP || n.roster.Revision != admitted.Revision {
		t.Fatal("automatic admission did not install the owner-approved roster and assigned IP")
	}
	if !n.p.Paused || n.wg != nil {
		t.Fatal("admission started a paused network")
	}
	data, err := os.ReadFile(n.path)
	if err != nil {
		t.Fatal(err)
	}
	var saved profile
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Pending || saved.Code != text || saved.LocalIP != admitted.Members[1].IP || !saved.Paused {
		t.Fatal("automatic admission was not persisted")
	}
}

func TestControlRosterRejectsInvalidAdmissionWithoutChangingSavedProfile(t *testing.T) {
	for _, name := range []string{"tampered signature", "different owner", "different session", "different network", "different mode", "wrong local WireGuard key", "stale revision", "header revision mismatch", "guest not admitted"} {
		t.Run(name, func(t *testing.T) {
			n, code, key := pendingAdmissionNode(t)
			headerRevision := code.Revision
			switch name {
			case "different owner":
				owner, ownerKey := testMember(t, "Other owner", code.Members[0].IP.String())
				code.Owner, code.Signer, code.Members[0], key = owner.Identity, owner.Identity, owner, ownerKey
			case "different session":
				code.Session = strings.Repeat("b2", 16)
			case "different network":
				code.Network = netip.MustParsePrefix("10.213.48.0/24")
				code.Members[0].IP, code.Members[1].IP = netip.MustParseAddr("10.213.48.1"), netip.MustParseAddr("10.213.48.3")
			case "different mode":
				code.Masked = !code.Masked
			case "wrong local WireGuard key":
				wrong, _ := testMember(t, "Wrong key", "")
				code.Members[1].WireGuard = wrong.WireGuard
			case "stale revision":
				n.roster.Revision = code.Revision + 1
				var err error
				n.p.Code, err = Encode(n.roster, key)
				if err != nil {
					t.Fatal(err)
				}
				if err := n.save(n.p); err != nil {
					t.Fatal(err)
				}
			case "header revision mismatch":
				headerRevision++
			case "guest not admitted":
				code.Members = code.Members[:1]
			}
			text, err := Encode(code, key)
			if err != nil {
				t.Fatal(err)
			}
			if name == "tampered signature" {
				at := len(text) - 8
				b := byte('A')
				if text[at] == b {
					b = 'B'
				}
				text = text[:at] + string(b) + text[at+1:]
			}
			beforeProfile, _ := json.Marshal(n.p)
			beforeRoster, _ := json.Marshal(n.roster)
			beforeFile, err := os.ReadFile(n.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.applyControlRoster(text, headerRevision); err == nil {
				t.Fatal("invalid automatic admission was accepted")
			}
			afterProfile, _ := json.Marshal(n.p)
			afterRoster, _ := json.Marshal(n.roster)
			afterFile, err := os.ReadFile(n.path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeProfile, afterProfile) || !bytes.Equal(beforeRoster, afterRoster) || !bytes.Equal(beforeFile, afterFile) || n.wg != nil {
				t.Fatal("rejected automatic admission changed the profile, roster or running tunnel")
			}
		})
	}
}

func TestPendingAdmissionRejectsOriginalInvitationAtSameRevision(t *testing.T) {
	n, _, _ := pendingAdmissionNode(t)
	before, err := os.ReadFile(n.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.applyControlRoster(n.p.Code, n.roster.Revision); err == nil || !strings.Contains(err.Error(), "прежнее приглашение") {
		t.Fatalf("repeated invitation did not explain pending admission: %v", err)
	}
	after, err := os.ReadFile(n.path)
	if err != nil {
		t.Fatal(err)
	}
	if !n.p.Pending || n.wg != nil || !bytes.Equal(before, after) {
		t.Fatal("repeated invitation changed pending admission")
	}
}
