//go:build windows

package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"directlan/internal/identity"
	"directlan/internal/localipc"
	"directlan/internal/tunnel"
)

func TestCopyNetworkCodeKeepsRevisionAndAcknowledgements(t *testing.T) {
	keys, code, text := lifecycleNetwork(t)
	n := node{keys: keys, roster: code, p: profile{Code: text, LocalIP: code.Members[0].IP},
		path: filepath.Join(t.TempDir(), "owner.mesh.json"), wg: &tunnel.Tunnel{}, scanned: true,
		endpoints: append([]netip.AddrPort(nil), code.Members[0].Endpoints...),
		confirmed: map[string]uint64{memberID(code.Members[1]): code.Revision}}
	if err := n.save(n.p); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(n.path)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		result, apiErr := n.handle(context.Background(), localipc.Request{Method: "mesh.code"})
		if apiErr != nil {
			t.Fatal(apiErr)
		}
		if result.(map[string]string)["code"] != text || n.roster.Revision != code.Revision || n.confirmed[memberID(code.Members[1])] != code.Revision {
			t.Fatal("copying an unchanged invitation changed its revision or acknowledgement")
		}
	}
	after, err := os.ReadFile(n.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("copying an unchanged code rewrote its saved profile: %v", err)
	}
}

func TestCopyNetworkCodeRefreshesOnlyChangedMetadataOrExpiry(t *testing.T) {
	for _, change := range []string{"endpoint", "expiry"} {
		t.Run(change, func(t *testing.T) {
			keys, code, text := lifecycleNetwork(t)
			endpoints := append([]netip.AddrPort(nil), code.Members[0].Endpoints...)
			if change == "endpoint" {
				endpoints = []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:50003")}
			} else {
				code.Expires = time.Now().Add(4 * time.Minute)
				var err error
				text, err = Encode(code, ed25519.PrivateKey(keys.IdentityPrivate))
				if err != nil {
					t.Fatal(err)
				}
			}
			n := node{keys: keys, roster: code, p: profile{Code: text, LocalIP: code.Members[0].IP},
				path: filepath.Join(t.TempDir(), "owner.mesh.json"), wg: &tunnel.Tunnel{}, scanned: true, endpoints: endpoints}
			result, apiErr := n.handle(context.Background(), localipc.Request{Method: "mesh.code"})
			if apiErr != nil {
				t.Fatal(apiErr)
			}
			refreshed := result.(map[string]string)["code"]
			if n.roster.Revision != code.Revision+1 || refreshed == text {
				t.Fatal("changed metadata was not signed with one new revision")
			}
			if _, err := Decode(refreshed, time.Now()); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				result, apiErr = n.handle(context.Background(), localipc.Request{Method: "mesh.code"})
				if apiErr != nil || result.(map[string]string)["code"] != refreshed || n.roster.Revision != code.Revision+1 {
					t.Fatal("repeated copy kept incrementing an already refreshed revision")
				}
			}
		})
	}
}

func TestAuthenticatedControlSourceFreshnessRefreshesAndResets(t *testing.T) {
	n := node{}
	now := time.Unix(1800000000, 0)
	endpoint := netip.MustParseAddrPort("8.8.8.8:50001")
	n.rememberControlEndpoint("member", endpoint, now.Add(-time.Minute))
	n.rememberControlEndpoint("member", endpoint, now)
	if !n.controlSources["member"].fresh(now.Add(44 * time.Second)) {
		t.Fatal("repeat authenticated response did not refresh source freshness")
	}
	n.rememberControlEndpoint("private", netip.MustParseAddrPort("192.168.1.2:50002"), now)
	if _, ok := n.controlSources["private"]; ok {
		t.Fatal("private source became an approved public fallback")
	}
	n.resetControl([16]byte{1}, [32]byte{2})
	if len(n.controlSources) != 0 {
		t.Fatal("new tunnel kept return-path evidence from a previous tunnel")
	}
}

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
