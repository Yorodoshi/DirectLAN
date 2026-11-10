package mesh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"directlan/internal/directpair"
)

const (
	MaxMembers     = 10
	codePrefix     = "DL3."
	maxCodeBytes   = 32 << 10
	maxEncodedSize = 44 << 10
)

type Member struct {
	Identity  []byte           `json:"identity"`
	WireGuard []byte           `json:"wireguard"`
	Name      string           `json:"name"`
	IP        netip.Addr       `json:"ip"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
}

type Code struct {
	Kind     string       `json:"kind"`
	Session  string       `json:"session"`
	Network  netip.Prefix `json:"network"`
	Owner    []byte       `json:"owner"`
	Signer   []byte       `json:"signer"`
	Masked   bool         `json:"masked"`
	Revision uint64       `json:"revision"`
	Members  []Member     `json:"members,omitempty"`
	Member   *Member      `json:"member,omitempty"`
	Expires  time.Time    `json:"expires"`
}

// Encode signs public network state or a membership request. A request alone
// never grants membership. The owner signs the admitted identity, key and IP
// together in a network code.
func Encode(code Code, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), code.Signer) {
		return "", errors.New("ключ подписи не соответствует коду DirectLAN")
	}
	if err := validateCode(code, time.Time{}); err != nil {
		return "", err
	}
	body, err := json.Marshal(code)
	if err != nil {
		return "", errors.New("не удалось сформировать код DirectLAN")
	}
	if len(body)+ed25519.SignatureSize > maxCodeBytes {
		return "", errors.New("код сети DirectLAN превышает допустимый размер")
	}
	message := append([]byte(codePrefix), body...)
	signature := ed25519.Sign(key, message)
	return codePrefix + base64.RawURLEncoding.EncodeToString(append(body, signature...)), nil
}

func Decode(text string, now time.Time) (Code, error) {
	var code Code
	encoded, ok := strings.CutPrefix(strings.TrimSpace(text), codePrefix)
	if !ok || len(encoded) > maxEncodedSize-len(codePrefix) {
		return code, errors.New("вставьте полный код сети DirectLAN, начинающийся с DL3.")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) <= ed25519.SignatureSize || len(raw) > maxCodeBytes {
		return code, errors.New("код DirectLAN повреждён или превышает допустимый размер")
	}
	body, signature := raw[:len(raw)-ed25519.SignatureSize], raw[len(raw)-ed25519.SignatureSize:]
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&code); err != nil {
		return Code{}, errors.New("неверный формат кода сети DirectLAN")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Code{}, errors.New("лишние данные в коде сети DirectLAN")
	}
	canonical, err := json.Marshal(code)
	if err != nil || !bytes.Equal(canonical, body) {
		return Code{}, errors.New("код сети DirectLAN содержит неоднозначные поля")
	}
	if !validIdentity(code.Signer) || !ed25519.Verify(code.Signer, append([]byte(codePrefix), body...), signature) {
		return Code{}, errors.New("подпись кода сети DirectLAN не совпадает")
	}
	if err := validateCode(code, now); err != nil {
		return Code{}, err
	}
	return code, nil
}

func validateCode(code Code, now time.Time) error {
	session, err := hex.DecodeString(code.Session)
	if err != nil || len(session) != 16 || hex.EncodeToString(session) != code.Session ||
		!code.Network.Addr().Is4() || !code.Network.Addr().IsPrivate() || code.Network.Bits() != 24 || code.Network.Masked() != code.Network ||
		!validIdentity(code.Owner) || !validIdentity(code.Signer) {
		return errors.New("неверные параметры сети DirectLAN")
	}
	if code.Expires.IsZero() || !now.IsZero() && (!now.Before(code.Expires) || code.Expires.After(now.Add(35*time.Minute))) {
		return errors.New("срок кода истёк или часы на ПК расходятся. Скопируйте свежий код")
	}
	switch code.Kind {
	case "network":
		if !bytes.Equal(code.Owner, code.Signer) || code.Member != nil || code.Revision == 0 || len(code.Members) == 0 || len(code.Members) > MaxMembers {
			return errors.New("неверный состав или подпись владельца сети DirectLAN")
		}
		if !bytes.Equal(code.Members[0].Identity, code.Owner) || code.Members[0].IP != code.Network.Addr().Next() {
			return errors.New("владелец сети должен занимать первый виртуальный адрес")
		}
		identities, keys, ips := make(map[string]bool), make(map[string]bool), make(map[netip.Addr]bool)
		for _, member := range code.Members {
			if err := validateMember(member, code.Network, false); err != nil {
				return err
			}
			id, key := string(member.Identity), string(member.WireGuard)
			if identities[id] || keys[key] || ips[member.IP] {
				return errors.New("в сети DirectLAN повторяется участник, ключ или виртуальный IP")
			}
			identities[id], keys[key], ips[member.IP] = true, true, true
		}
	case "request":
		if code.Member == nil || len(code.Members) != 0 || !bytes.Equal(code.Member.Identity, code.Signer) || bytes.Equal(code.Owner, code.Signer) {
			return errors.New("неверная заявка участника DirectLAN")
		}
		return validateMember(*code.Member, code.Network, true)
	default:
		return errors.New("неизвестный тип кода сети DirectLAN")
	}
	return nil
}

func validateMember(member Member, network netip.Prefix, provisional bool) error {
	if !validIdentity(member.Identity) || !validWireGuardKey(member.WireGuard) {
		return errors.New("код участника содержит недопустимый открытый ключ")
	}
	if err := validateName(member.Name); err != nil {
		return err
	}
	if !provisional || member.IP.IsValid() {
		if !member.IP.Is4() || !network.Contains(member.IP) || member.IP == network.Addr() || member.IP.As4()[3] == 255 {
			return errors.New("виртуальный адрес участника находится за пределами сети")
		}
	}
	if len(member.Endpoints) > 4 {
		return errors.New("слишком много внешних адресов участника")
	}
	seen := make(map[netip.AddrPort]bool)
	for _, endpoint := range member.Endpoints {
		if !directpair.PublicEndpoint(endpoint) || endpoint.Addr().Is4In6() || seen[endpoint] {
			return errors.New("код участника содержит недопустимый или повторный внешний адрес")
		}
		seen[endpoint] = true
	}
	return nil
}

func validateName(name string) error {
	if !utf8.ValidString(name) || name == "" || strings.TrimSpace(name) != name || utf8.RuneCountInString(name) > 64 {
		return errors.New("имя участника должно содержать от 1 до 64 символов")
	}
	for _, char := range name {
		if unicode.IsControl(char) {
			return errors.New("имя участника содержит управляющие символы")
		}
	}
	return nil
}

func validIdentity(key []byte) bool {
	return len(key) == ed25519.PublicKeySize && !bytes.Equal(key, make([]byte, ed25519.PublicKeySize))
}

func validWireGuardKey(key []byte) bool {
	public, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return false
	}
	// ECDH rejects low-order public keys by checking the resulting shared value.
	var scalar [32]byte
	scalar[0] = 1
	private, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return false
	}
	_, err = private.ECDH(public)
	return err == nil
}
