//go:build windows

package service

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"directlan/internal/client"
	"directlan/internal/coordinator"
	"directlan/internal/localipc"
)

func TestUIActionsMembership(t *testing.T) {
	store, err := coordinator.OpenStore(filepath.Join(t.TempDir(), "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(coordinator.NewServer(store, true))
	defer server.Close()
	s, err := New(Config{CoordinatorURL: server.URL, IdentityPath: filepath.Join(t.TempDir(), "identity.dat"), DeviceName: "Owner", DevHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	call := func(method string, params any) any {
		t.Helper()
		raw, _ := json.Marshal(params)
		result, e := s.Handle(ctx, localipc.Request{Version: 1, ID: "test", Method: method, Params: raw})
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	group := call("group.create", map[string]string{"name": "Test"}).(coordinator.Snapshot)
	invite := call("invite.create", struct{}{}).(map[string]any)["token"].(string)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	wg, _ := ecdh.X25519().GenerateKey(rand.Reader)
	peer, err := client.New(server.URL, key, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = peer.Join(ctx, invite, base64.StdEncoding.EncodeToString(wg.PublicKey().Bytes()), "Peer")
	if err != nil {
		t.Fatal(err)
	}
	s.refresh(ctx)
	status := s.status()
	var pending PeerStatus
	for _, member := range status.Members {
		if !member.Approved {
			pending = member
		}
	}
	if pending.DeviceID == "" || pending.Fingerprint == "" {
		t.Fatal("UI has no pending fingerprint")
	}
	call("member.approve", map[string]string{"device_id": pending.DeviceID, "fingerprint": pending.Fingerprint})
	snapshot, err := peer.Group(ctx, group.NetworkID)
	if err != nil || len(snapshot.Members) != 2 {
		t.Fatalf("approve: %v", err)
	}
	call("member.revoke", map[string]string{"device_id": pending.DeviceID})
	if _, err := peer.Group(ctx, group.NetworkID); err == nil {
		t.Fatal("revoked member still authorized")
	}
	report, _ := json.Marshal(call("diagnostics.export", struct{}{}))
	var exported map[string]any
	if json.Unmarshal(report, &exported) != nil {
		t.Fatal("invalid diagnostics")
	}
}
