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

	"directlan/internal/identity"
	"directlan/internal/localipc"
)

func TestStoppedTunnelDoesNotReportConnectedMembers(t *testing.T) {
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	roster, _ := testNetwork(t)
	remote := roster.Members[1]
	n := node{keys: keys, p: profile{Code: "saved-network"}, roster: roster,
		members: map[string]memberStatus{memberID(remote): {State: "connected", RTT: 12, Checking: true}}}
	data, err := json.Marshal(n.status())
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		State   string         `json:"state"`
		Members []memberStatus `json:"members"`
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.State == "connected" {
		t.Fatal("stopped tunnel reported a connected network")
	}
	for _, member := range status.Members {
		if member.State == "connected" || member.RTT != 0 || member.Checking {
			t.Fatal("stopped tunnel reported a connected or active peer")
		}
	}
}

func TestRestoreKeepsSignedNetworkWhenLocalKeyNoLongerMatches(t *testing.T) {
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	roster, _ := testNetwork(t)
	roster.Owner, roster.Signer = keys.IdentityPublic(), keys.IdentityPublic()
	roster.Members[0].Identity = keys.IdentityPublic()
	currentPublic, err := keys.WireGuardPublic()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(currentPublic, roster.Members[0].WireGuard) {
		t.Fatal("fixture must use a different admitted WireGuard key")
	}
	text, err := Encode(roster, ed25519.PrivateKey(keys.IdentityPrivate))
	if err != nil {
		t.Fatal(err)
	}
	saved := profile{Code: text, Name: roster.Members[0].Name, LocalIP: roster.Members[0].IP}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "saved.mesh.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	n := node{keys: keys, path: path, wake: make(chan struct{}, 1)}
	if err := n.restore(); err == nil || !strings.Contains(err.Error(), "ключ") {
		t.Fatalf("restore must reject the mismatched key before driver startup: %v", err)
	}
	if n.p.Code != text || n.roster.Session != roster.Session || n.roster.Revision != roster.Revision || n.wg != nil {
		t.Fatal("failed startup lost the signed network or retained a tunnel")
	}
	if _, err := n.handle(context.Background(), localipc.Request{Method: "mesh.create"}); err == nil {
		t.Fatal("new network could overwrite a saved network after failed startup")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("failed restore changed the saved network: %v", err)
	}
}

func TestFullNetworkRejectsJoinEvenWithUnusedLowAddress(t *testing.T) {
	roster, ownerKey := testNetwork(t)
	roster.Members[1].IP = netip.MustParseAddr("10.213.47.20")
	roster.Members[2].IP = netip.MustParseAddr("10.213.47.21")
	for len(roster.Members) < MaxMembers {
		address := roster.Members[len(roster.Members)-1].IP.Next()
		member, _ := testMember(t, "PC", address.String())
		roster.Members = append(roster.Members, member)
	}
	text, err := Encode(roster, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "new.mesh.json")
	n := node{keys: keys, path: path, wake: make(chan struct{}, 1)}
	params, err := json.Marshal(map[string]any{"name": "new PC", "code": text})
	if err != nil {
		t.Fatal(err)
	}
	_, apiErr := n.handle(context.Background(), localipc.Request{Method: "mesh.join", Params: params})
	if apiErr == nil || !strings.Contains(apiErr.Message, "10") {
		t.Fatalf("full network did not reject join before driver startup: %v", apiErr)
	}
	if n.wg != nil || n.p.Code != "" {
		t.Fatal("rejected join changed runtime membership")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected join wrote a profile: %v", err)
	}
}

func TestJoiningRejectsInvalidNameBeforeOpeningInvitation(t *testing.T) {
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{strings.Repeat("я", 65), "PC\nspoofed"} {
		n := node{keys: keys}
		params, err := json.Marshal(map[string]any{"name": name, "code": "not-an-invitation"})
		if err != nil {
			t.Fatal(err)
		}
		_, apiErr := n.handle(context.Background(), localipc.Request{Method: "mesh.join", Params: params})
		if apiErr == nil || !strings.Contains(strings.ToLower(apiErr.Message), "имя") {
			t.Fatalf("invalid name reached invitation processing: %v", apiErr)
		}
	}
}
