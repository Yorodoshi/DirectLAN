package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"directlan/internal/coordinator"
)

func TestSignedMembershipLifecycle(t *testing.T) {
	store, err := coordinator.OpenStore(filepath.Join(t.TempDir(), "coordinator.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := coordinator.NewServer(store, false)
	handler.EnableHTTPSRelay = true
	server := httptest.NewUnstartedServer(handler)
	server.Config.ReadTimeout = 500 * time.Millisecond
	server.Config.WriteTimeout = 500 * time.Millisecond
	server.StartTLS()
	defer server.Close()
	newClient := func() (*Client, string) {
		t.Helper()
		_, identityKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wgKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		client, err := New(server.URL, identityKey, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.SetTrustedCA(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})); err != nil {
			t.Fatal(err)
		}
		return client, base64.StdEncoding.EncodeToString(wgKey.PublicKey().Bytes())
	}
	owner, ownerWG := newClient()
	peer, peerWG := newClient()
	ctx := context.Background()
	group, err := owner.CreateGroup(ctx, "Friends", "10.231.42.0/24", ownerWG, "10.231.42.1")
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := owner.CreateInvitation(ctx, group.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	join, err := peer.Join(ctx, invitation.Invitation, peerWG, "Peer")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := owner.Pending(ctx, group.NetworkID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending: %v, %v", pending, err)
	}
	if pending[0].PendingID != join.PendingID {
		t.Fatal("join pending ID mismatch")
	}
	group, err = owner.Approve(ctx, group.NetworkID, join.PendingID, pending[0].Fingerprint, "10.231.42.2")
	if err != nil || len(group.Members) != 2 {
		t.Fatalf("approve: %v, %v", group, err)
	}
	peerGroup, err := peer.Group(ctx, group.NetworkID)
	if err != nil || peerGroup.Revision != group.Revision {
		t.Fatalf("peer snapshot: %v, %v", peerGroup, err)
	}
	if _, err := peer.Heartbeat(ctx, group.NetworkID); err != nil {
		t.Fatal(err)
	}
	var peerID string
	for _, member := range group.Members {
		if member.OverlayIP == "10.231.42.2" {
			peerID = member.DeviceID
		}
	}
	if peerID == "" {
		t.Fatal("peer missing")
	}
	ownerConn, err := owner.Relay(ctx, group.NetworkID, peerID, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerConn.Close()
	peerConn, err := peer.Relay(ctx, group.NetworkID, group.OwnerDeviceID, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	time.Sleep(750 * time.Millisecond) // upgraded sockets must outlive HTTP deadlines
	_ = peerConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0xa5}, 1420)
	if _, err := ownerConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := peerConn.Read(buffer)
	if err != nil || !bytes.Equal(payload, buffer[:n]) {
		t.Fatalf("relay changed datagram: %v", err)
	}
	_, err = owner.SendSignal(ctx, group.NetworkID, peerID, coordinator.Signal{
		ICEUfrag: "abcd1234", ICEPwd: "abcdefghijklmnopqrstuvwxyz",
		Candidates: []string{"candidate:1 1 udp 1234 192.0.2.1 12345 typ host"},
		Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	signals, err := peer.Signals(ctx, group.NetworkID, 0, group.Revision, 0)
	if err != nil || len(signals.Signals) != 1 {
		t.Fatalf("signals: %v, %v", signals, err)
	}
	group, err = owner.Revoke(ctx, group.NetworkID, peerID)
	if err != nil || len(group.Members) != 1 {
		t.Fatalf("revoke: %v, %v", group, err)
	}
	if _, err := peer.Group(ctx, group.NetworkID); err == nil {
		t.Fatal("revoked peer kept group access")
	}
}
