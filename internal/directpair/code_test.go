package directpair

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSignedCodeCarriesOnlyPublicEndpoint(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := Code{Session: strings.Repeat("a", 32), Host: true, Identity: public, WireGuard: make([]byte, 32),
		Network: netip.MustParsePrefix("172.21.51.4/30"), Expires: now.Add(time.Minute),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:51820")}}
	code.WireGuard[0] = 5
	text, err := Encode(code, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(text, now)
	if err != nil || len(got.Endpoints) != 1 || got.Endpoints[0] != code.Endpoints[0] {
		t.Fatalf("decode: %v", err)
	}
	if _, err := Decode(text, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired invitation accepted")
	}
	tampered := []byte(text)
	if tampered[len(tampered)-10] == 'a' {
		tampered[len(tampered)-10] = 'b'
	} else {
		tampered[len(tampered)-10] = 'a'
	}
	if _, err := Decode(string(tampered), now); err == nil {
		t.Fatal("modified signature accepted")
	}
	for _, addr := range []string{"192.168.31.158:4433", "100.64.1.2:51820", "[fd00::1]:51820"} {
		code.Endpoints = []netip.AddrPort{netip.MustParseAddrPort(addr)}
		text, _ = Encode(code, key)
		if _, err := Decode(text, now); err == nil {
			t.Fatalf("private endpoint accepted: %s", addr)
		}
	}
}
