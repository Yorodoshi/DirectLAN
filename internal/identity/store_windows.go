//go:build windows

package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxIdentityFile = 64 << 10

type State struct {
	IdentityPrivate  []byte            `json:"identity_private"`
	WireGuardPrivate []byte            `json:"wireguard_private"`
	NetworkID        string            `json:"network_id,omitempty"`
	Revision         uint64            `json:"revision,omitempty"`
	SnapshotHash     string            `json:"snapshot_hash,omitempty"`
	OwnerFingerprint string            `json:"owner_fingerprint,omitempty"`
	AdapterID        string            `json:"adapter_id,omitempty"`
	MemberPins       map[string]string `json:"member_pins,omitempty"`
}

func (s State) IdentityPublic() ed25519.PublicKey {
	return ed25519.PrivateKey(s.IdentityPrivate).Public().(ed25519.PublicKey)
}

func (s State) WireGuardPublic() ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(s.WireGuardPrivate)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

func (s State) WireGuardPublicBase64() (string, error) {
	key, err := s.WireGuardPublic()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func (s State) Validate() error {
	if len(s.IdentityPrivate) != ed25519.PrivateKeySize {
		return errors.New("invalid identity private key")
	}
	if len(s.WireGuardPrivate) != 32 {
		return errors.New("invalid WireGuard private key")
	}
	_, err := s.WireGuardPublic()
	return err
}

func Generate() (State, error) {
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return State{}, err
	}
	wg, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return State{}, err
	}
	return State{IdentityPrivate: identity, WireGuardPrivate: wg.Bytes()}, nil
}

// LoadOrCreate keeps both private keys encrypted with the current Windows
// account's DPAPI key. A service must always use the same service account.
func LoadOrCreate(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) == 0 || len(data) > maxIdentityFile {
			return State{}, errors.New("identity file has invalid size")
		}
		clear, err := unprotect(data)
		if err != nil {
			return State{}, fmt.Errorf("DPAPI decrypt identity: %w", err)
		}
		var state State
		if err := json.Unmarshal(clear, &state); err != nil {
			return State{}, err
		}
		return state, state.Validate()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	state, err := Generate()
	if err != nil {
		return State{}, err
	}
	if err = Save(path, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func Save(path string, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	clear, err := json.Marshal(state)
	if err != nil {
		return err
	}
	ciphertext, err := protect(clear)
	if err != nil {
		return err
	}
	return WritePrivateFile(path, ciphertext)
}

// WritePrivateFile atomically writes a file with a protected Windows DACL.
// Existing parent directory permissions are preserved.
func WritePrivateFile(path string, data []byte) error {
	parent := filepath.Dir(path)
	_, parentErr := os.Stat(parent)
	newDirectory := errors.Is(parentErr, os.ErrNotExist)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	if newDirectory {
		if err := lockToCurrentAccount(parent); err != nil {
			return fmt.Errorf("secure identity directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(parent, ".identity-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := lockToCurrentAccount(tmp.Name()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func protect(data []byte) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}

func unprotect(data []byte) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}

func lockToCurrentAccount(path string) error {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	flags := ""
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)(A;" + flags + ";FA;;;" + tokenUser.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
