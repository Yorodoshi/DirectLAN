package mesh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testMember(t *testing.T, name string, ip string) (Member, ed25519.PrivateKey) {
	t.Helper()
	identity, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wireguard, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member := Member{Identity: identity, WireGuard: wireguard.PublicKey().Bytes(), Name: name}
	if ip != "" {
		member.IP = netip.MustParseAddr(ip)
	}
	return member, signingKey
}

func testNetwork(t *testing.T) (Code, ed25519.PrivateKey) {
	t.Helper()
	owner, key := testMember(t, "Москва", "10.213.47.1")
	second, _ := testMember(t, "New York", "10.213.47.2")
	third, _ := testMember(t, "Tokyo", "10.213.47.3")
	owner.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:50001")}
	second.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("[2606:4700:4700::1111]:50002")}
	return Code{Kind: "network", Session: strings.Repeat("a1", 16), Network: netip.MustParsePrefix("10.213.47.0/24"),
		Owner: owner.Identity, Signer: owner.Identity, Masked: true, Revision: 1,
		Members: []Member{owner, second, third}, Expires: time.Now().UTC().Add(30 * time.Minute)}, key
}

func signedBody(t *testing.T, body []byte, key ed25519.PrivateKey) string {
	t.Helper()
	signature := ed25519.Sign(key, append([]byte(codePrefix), body...))
	return codePrefix + base64.RawURLEncoding.EncodeToString(append(body, signature...))
}

func uncheckedCode(t *testing.T, code Code, key ed25519.PrivateKey) string {
	t.Helper()
	body, err := json.Marshal(code)
	if err != nil {
		t.Fatal(err)
	}
	return signedBody(t, body, key)
}

func TestNetworkAndRequestRoundTrip(t *testing.T) {
	network, ownerKey := testNetwork(t)
	now := time.Now()
	text, err := Encode(network, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(text, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Members) != 3 || decoded.Revision != 1 || !decoded.Masked || decoded.Members[1].IP != network.Members[1].IP {
		t.Fatalf("network changed during decoding: %+v", decoded)
	}
	guest, guestKey := testMember(t, "Laptop", "")
	request := Code{Kind: "request", Session: network.Session, Network: network.Network, Owner: network.Owner,
		Signer: guest.Identity, Masked: true, Revision: network.Revision, Member: &guest, Expires: network.Expires}
	text, err = Encode(request, guestKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = Decode(text, now)
	if err != nil || decoded.Member == nil || decoded.Member.IP.IsValid() {
		t.Fatalf("request without assigned IP failed: %v", err)
	}
	guest.IP = netip.MustParseAddr("10.213.47.4")
	text, err = Encode(request, guestKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(text, now); err != nil {
		t.Fatalf("request with provisional IP failed: %v", err)
	}
	if _, err := Decode(text, now.Add(31*time.Minute)); err == nil {
		t.Fatal("expired code accepted for a new import")
	}
	if _, err := Decode(text, time.Time{}); err != nil {
		t.Fatalf("trusted saved code could not be restored: %v", err)
	}
}

func TestRejectsUnauthorizedNetworkState(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*Code)
	}{
		{"duplicate identity", func(code *Code) { code.Members[2].Identity = code.Members[1].Identity }},
		{"duplicate WireGuard key", func(code *Code) { code.Members[2].WireGuard = code.Members[1].WireGuard }},
		{"duplicate IP", func(code *Code) { code.Members[2].IP = code.Members[1].IP }},
		{"wrong owner address", func(code *Code) { code.Members[0].IP = netip.MustParseAddr("10.213.47.4") }},
		{"wrong owner member", func(code *Code) { code.Members[0], code.Members[1] = code.Members[1], code.Members[0] }},
		{"zero revision", func(code *Code) { code.Revision = 0 }},
		{"unassigned IP", func(code *Code) { code.Members[1].IP = netip.Addr{} }},
		{"network address", func(code *Code) { code.Members[1].IP = code.Network.Addr() }},
		{"broadcast address", func(code *Code) { code.Members[1].IP = netip.MustParseAddr("10.213.47.255") }},
		{"foreign network", func(code *Code) { code.Members[1].IP = netip.MustParseAddr("10.213.48.2") }},
		{"zero WireGuard key", func(code *Code) { code.Members[1].WireGuard = make([]byte, 32) }},
		{"low-order WireGuard key", func(code *Code) { code.Members[1].WireGuard = append([]byte{1}, make([]byte, 31)...) }},
		{"zero identity", func(code *Code) { code.Members[1].Identity = make([]byte, 32) }},
		{"private endpoint", func(code *Code) {
			code.Members[1].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.168.1.2:50000")}
		}},
		{"CGNAT endpoint", func(code *Code) {
			code.Members[1].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("100.64.2.3:50000")}
		}},
		{"mapped IPv4 endpoint", func(code *Code) {
			code.Members[1].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("[::ffff:8.8.8.8]:50000")}
		}},
		{"duplicate endpoint", func(code *Code) {
			code.Members[1].Endpoints = append(code.Members[1].Endpoints, code.Members[1].Endpoints[0])
		}},
		{"control in name", func(code *Code) { code.Members[1].Name = "name\nspoofed" }},
		{"long name", func(code *Code) { code.Members[1].Name = strings.Repeat("я", 65) }},
		{"public subnet", func(code *Code) { code.Network = netip.MustParsePrefix("8.8.8.0/24") }},
		{"legacy subnet", func(code *Code) { code.Network = netip.MustParsePrefix("10.213.47.0/30") }},
		{"unmasked subnet", func(code *Code) { code.Network = netip.MustParsePrefix("10.213.47.1/24") }},
		{"request data in roster", func(code *Code) { code.Member = &code.Members[1] }},
		{"unknown kind", func(code *Code) { code.Kind = "invitation" }},
		{"missing expiry", func(code *Code) { code.Expires = time.Time{} }},
		{"excessive lifetime", func(code *Code) { code.Expires = time.Now().Add(36 * time.Minute) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			code, key := testNetwork(t)
			mutation.change(&code)
			if _, err := Decode(uncheckedCode(t, code, key), time.Now()); err == nil {
				t.Fatal("owner-signed malformed network accepted")
			}
		})
	}
	code, _ := testNetwork(t)
	_, intruderKey := testMember(t, "Intruder", "10.213.47.4")
	code.Signer = intruderKey.Public().(ed25519.PublicKey)
	if _, err := Decode(uncheckedCode(t, code, intruderKey), time.Now()); err == nil {
		t.Fatal("non-owner signature granted network membership")
	}
}

func TestRejectsAmbiguousAndCorruptCode(t *testing.T) {
	code, key := testNetwork(t)
	body, err := json.Marshal(code)
	if err != nil {
		t.Fatal(err)
	}
	for _, badBody := range [][]byte{
		append(append([]byte(nil), body...), []byte("{}")...),
		bytes.Replace(body, []byte(`"kind":"network"`), []byte(`"kind":"request","kind":"network"`), 1),
		bytes.Replace(body, []byte(`"kind":"network"`), []byte(`"kind":"network","ignored":true`), 1),
		bytes.Replace(body, []byte(`"masked":true`), []byte(`"masked": false, "masked":true`), 1),
		append([]byte(" "), body...),
	} {
		if _, err := Decode(signedBody(t, badBody, key), time.Now()); err == nil {
			t.Fatal("ambiguous or unknown signed JSON accepted")
		}
	}
	text, err := Encode(code, key)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, codePrefix))
	if err != nil {
		t.Fatal(err)
	}
	tampered[len(tampered)-1] ^= 1
	if _, err := Decode(codePrefix+base64.RawURLEncoding.EncodeToString(tampered), time.Now()); err == nil {
		t.Fatal("modified signature accepted")
	}
	if _, err := Decode(codePrefix+strings.Repeat("A", maxEncodedSize), time.Now()); err == nil {
		t.Fatal("oversized code accepted")
	}
	if _, err := Encode(code, key[:32]); err == nil {
		t.Fatal("invalid signing key accepted")
	}
	code.Members[1].Name = string([]byte{0xff})
	if _, err := Encode(code, key); err == nil {
		t.Fatal("invalid UTF-8 member name encoded")
	}
}

func TestNetworkSizeAndRequestAuthority(t *testing.T) {
	code, ownerKey := testNetwork(t)
	for len(code.Members) < MaxMembers {
		ip := code.Members[len(code.Members)-1].IP.Next()
		member, _ := testMember(t, "PC", ip.String())
		code.Members = append(code.Members, member)
	}
	if _, err := Encode(code, ownerKey); err != nil {
		t.Fatalf("ten computers rejected: %v", err)
	}
	extra, _ := testMember(t, "extra", "10.213.47.11")
	code.Members = append(code.Members, extra)
	if _, err := Decode(uncheckedCode(t, code, ownerKey), time.Now()); err == nil {
		t.Fatal("network over ten computers accepted")
	}
	guest, guestKey := testMember(t, "PC", "10.213.47.2")
	request := Code{Kind: "request", Session: code.Session, Network: code.Network, Owner: code.Owner,
		Signer: guest.Identity, Member: &guest, Expires: code.Expires}
	request.Members = code.Members[:1]
	if _, err := Decode(uncheckedCode(t, request, guestKey), time.Now()); err == nil {
		t.Fatal("request carrying an admitted roster accepted")
	}
	request.Members = nil
	request.Owner = guest.Identity
	if _, err := Decode(uncheckedCode(t, request, guestKey), time.Now()); err == nil {
		t.Fatal("owner accepted as new joining member")
	}
}
