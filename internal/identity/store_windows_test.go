//go:build windows

package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.dat")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, first.IdentityPrivate) || bytes.Contains(stored, first.WireGuardPrivate) {
		t.Fatal("private key appears in the encrypted file")
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.IdentityPrivate, second.IdentityPrivate) || !bytes.Equal(first.WireGuardPrivate, second.WireGuardPrivate) {
		t.Fatal("identity changed on reload")
	}
	first.NetworkID = "network-test"
	if err := Save(path, first); err != nil {
		t.Fatal(err)
	}
	third, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if third.NetworkID != first.NetworkID {
		t.Fatal("state update not persisted")
	}
}

func TestSavePreservesSiblingPermissions(t *testing.T) {
	dir := t.TempDir()
	sibling := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(sibling, []byte("retain access"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(filepath.Join(dir, "identity.dat"), state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(sibling); err != nil {
		t.Fatalf("identity storage changed sibling permissions: %v", err)
	}
}
