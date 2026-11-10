//go:build windows

package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"directlan/internal/identity"
	"directlan/internal/localipc"
	"directlan/internal/tunnel"
)

func lifecycleNetwork(t *testing.T) (identity.State, Code, string) {
	t.Helper()
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, _ := testNetwork(t)
	public, err := keys.WireGuardPublic()
	if err != nil {
		t.Fatal(err)
	}
	code.Owner, code.Signer = keys.IdentityPublic(), keys.IdentityPublic()
	code.Members[0].Identity, code.Members[0].WireGuard = keys.IdentityPublic(), public
	text, err := Encode(code, ed25519.PrivateKey(keys.IdentityPrivate))
	if err != nil {
		t.Fatal(err)
	}
	return keys, code, text
}

func lifecycleStatus(t *testing.T, result any) struct {
	State     string         `json:"state"`
	Paused    bool           `json:"paused"`
	CodeReady bool           `json:"code_ready"`
	Members   []memberStatus `json:"members"`
} {
	t.Helper()
	var status struct {
		State     string         `json:"state"`
		Paused    bool           `json:"paused"`
		CodeReady bool           `json:"code_ready"`
		Members   []memberStatus `json:"members"`
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestRestorePausedNetworkKeepsAdmissionWithoutStartingTunnel(t *testing.T) {
	keys, code, text := lifecycleNetwork(t)
	saved := profile{
		Code: text, Name: code.Members[0].Name, LocalIP: code.Members[0].IP, Paused: true, Port: 54321,
		Learned: map[string]netip.AddrPort{memberID(code.Members[1]): netip.MustParseAddrPort("8.8.8.8:50001")},
	}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "paused.mesh.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	n := node{keys: keys, path: path, wake: make(chan struct{}, 1)}
	if err := n.restore(); err != nil {
		t.Fatal(err)
	}
	if n.wg != nil || !n.p.Paused || n.p.Code != text || n.p.LocalIP != saved.LocalIP || n.p.Port != saved.Port {
		t.Fatal("restoring a paused network lost its admission or started a tunnel")
	}
	if n.roster.Revision != code.Revision || len(n.roster.Members) != len(code.Members) || len(n.p.Learned) != 1 {
		t.Fatal("paused restore changed the admitted roster or learned endpoints")
	}
	status := lifecycleStatus(t, n.status())
	if status.State != "paused" || !status.Paused || status.CodeReady || n.discovery != "" {
		t.Fatal("paused restore reported an active network or address search")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var restored profile
	if err := json.Unmarshal(persisted, &restored); err != nil || !restored.Paused || restored.Code != text {
		t.Fatal("pause was not retained in the saved profile")
	}
}

func TestLifecycleCommandsRequireSavedNetwork(t *testing.T) {
	keys, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"mesh.disconnect", "mesh.resume", "mesh.restart"} {
		t.Run(method, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "absent.mesh.json")
			n := node{keys: keys, path: path}
			_, apiErr := n.handle(context.Background(), localipc.Request{Method: method})
			if apiErr == nil || apiErr.Code != "MESH" || n.wg != nil || n.p.Code != "" {
				t.Fatal("lifecycle command without a network changed state or succeeded")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("lifecycle command without a network wrote a profile")
			}
		})
	}
}

func TestPausedStatusNeverReportsCachedConnections(t *testing.T) {
	keys, code, text := lifecycleNetwork(t)
	for _, runtime := range []struct {
		name string
		wg   *tunnel.Tunnel
	}{{"stopped", nil}, {"stale runtime", &tunnel.Tunnel{}}} {
		t.Run(runtime.name, func(t *testing.T) {
			remote := code.Members[1]
			n := node{
				keys: keys, p: profile{Code: text, Paused: true}, roster: code, wg: runtime.wg, scanned: true,
				members: map[string]memberStatus{memberID(remote): {
					State: "connected", RTT: 12, Checking: true, LastProbe: time.Now(),
				}},
			}
			status := lifecycleStatus(t, n.status())
			if status.State != "paused" || !status.Paused || status.CodeReady {
				t.Fatal("paused network reported active actions")
			}
			for _, member := range status.Members {
				if member.State == "connected" || member.RTT != 0 || member.Checking {
					t.Fatal("paused network exposed a cached successful link or pending probe")
				}
			}
		})
	}
}

func TestDisconnectAlreadyPausedPreservesProfile(t *testing.T) {
	keys, code, text := lifecycleNetwork(t)
	path := filepath.Join(t.TempDir(), "paused.mesh.json")
	n := node{keys: keys, path: path, p: profile{Code: text, Paused: true}, roster: code}
	if err := n.save(n.p); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, apiErr := n.handle(context.Background(), localipc.Request{Method: "mesh.disconnect"})
	if apiErr != nil || !lifecycleStatus(t, result).Paused || n.wg != nil {
		t.Fatal("disconnecting an already paused network changed its lifecycle")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("repeated disconnect changed the saved profile")
	}
}

func TestAcceptingMemberWhilePausedKeepsConnectionsStopped(t *testing.T) {
	keys, code, text := lifecycleNetwork(t)
	n := node{
		keys: keys, path: filepath.Join(t.TempDir(), "paused.mesh.json"),
		p:      profile{Code: text, Name: code.Members[0].Name, LocalIP: code.Members[0].IP, Paused: true},
		roster: code, wake: make(chan struct{}, 1),
	}
	guest, guestKey := testMember(t, "New PC", "")
	request := Code{
		Kind: "request", Session: code.Session, Network: code.Network, Owner: code.Owner, Signer: guest.Identity,
		Masked: code.Masked, Revision: code.Revision, Member: &guest, Expires: time.Now().Add(time.Minute),
	}
	requestText, err := Encode(request, guestKey)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(map[string]string{"code": requestText})
	if err != nil {
		t.Fatal(err)
	}
	result, apiErr := n.handle(context.Background(), localipc.Request{Method: "mesh.accept", Params: params})
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	if n.wg != nil || !n.p.Paused || !lifecycleStatus(t, result).Paused || len(n.roster.Members) != len(code.Members)+1 {
		t.Fatal("approving a participant resumed a paused network or lost membership")
	}
	if n.roster.Revision <= code.Revision {
		t.Fatal("approved membership did not advance the signed roster")
	}
}
