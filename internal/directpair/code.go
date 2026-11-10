package directpair

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
)

const prefix = "DL2."

type Code struct {
	Session   string           `json:"session"`
	Network   netip.Prefix     `json:"network"`
	Host      bool             `json:"host"`
	Identity  []byte           `json:"identity"`
	WireGuard []byte           `json:"wireguard"`
	For       []byte           `json:"for,omitempty"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
	Expires   time.Time        `json:"expires"`
}

// Encode signs the complete invitation. The public key still needs to be
// received via a trusted conversation with the other participant.
func Encode(code Code, key ed25519.PrivateKey) (string, error) {
	body, err := json.Marshal(code)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, append([]byte(prefix), body...))
	return prefix + base64.RawURLEncoding.EncodeToString(append(body, sig...)), nil
}

func Decode(text string, now time.Time) (Code, error) {
	var code Code
	encoded, ok := strings.CutPrefix(strings.TrimSpace(text), prefix)
	if !ok || len(encoded) > 4096 {
		return code, errors.New("вставьте полный код DirectLAN, который начинается с DL2.")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) <= ed25519.SignatureSize {
		return code, errors.New("код повреждён или скопирован не полностью")
	}
	body := raw[:len(raw)-ed25519.SignatureSize]
	sig := raw[len(body):]
	if json.Unmarshal(body, &code) != nil || len(code.Identity) != ed25519.PublicKeySize || !ed25519.Verify(code.Identity, append([]byte(prefix), body...), sig) {
		return Code{}, errors.New("подпись кода не совпадает")
	}
	id, err := hex.DecodeString(code.Session)
	if err != nil || len(id) != 16 || !code.Network.Addr().Is4() || !code.Network.Addr().IsPrivate() || code.Network.Bits() != 30 || code.Network.Masked() != code.Network || len(code.WireGuard) != 32 || len(code.Endpoints) > 4 {
		return Code{}, errors.New("неверные параметры пары DirectLAN")
	}
	if code.Host && len(code.For) != 0 || !code.Host && len(code.For) != ed25519.PublicKeySize {
		return Code{}, errors.New("неверная роль в коде DirectLAN")
	}
	if code.Expires.IsZero() || !now.IsZero() && (!now.Before(code.Expires) || code.Expires.After(now.Add(35*time.Minute))) {
		return Code{}, errors.New("срок кода истёк или часы на компьютерах расходятся. Скопируйте новый код")
	}
	for _, endpoint := range code.Endpoints {
		if !PublicEndpoint(endpoint) {
			return Code{}, errors.New("код содержит недоступный из интернета адрес")
		}
	}
	return code, nil
}

var nonPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
}

func PublicEndpoint(endpoint netip.AddrPort) bool {
	addr := endpoint.Addr().Unmap()
	if endpoint.Port() == 0 || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Zone() != "" {
		return false
	}
	if addr.Is4() {
		for _, p := range nonPublicIPv4 {
			if p.Contains(addr) {
				return false
			}
		}
		return true
	}
	return netip.MustParsePrefix("2000::/3").Contains(addr) && !netip.MustParsePrefix("2001:db8::/32").Contains(addr)
}
