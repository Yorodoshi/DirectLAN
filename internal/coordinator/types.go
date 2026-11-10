package coordinator

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// Member contains only public information. IdentityPublicKey authenticates API
// requests; PublicKey is the separate WireGuard key used by the tunnel.
type Member struct {
	DeviceID          string    `json:"device_id"`
	IdentityPublicKey string    `json:"identity_public_key"`
	PublicKey         string    `json:"public_key"`
	OverlayIP         string    `json:"overlay_ip"`
	DeviceName        string    `json:"device_name"`
	JoinedAt          time.Time `json:"joined_at"`
}

type Snapshot struct {
	NetworkID     string   `json:"network_id"`
	Name          string   `json:"name"`
	NetworkCIDR   string   `json:"network_cidr"`
	Revision      uint64   `json:"revision"`
	OwnerDeviceID string   `json:"owner_device_id"`
	Members       []Member `json:"members"`
}

type PendingInfo struct {
	PendingID         string    `json:"pending_id"`
	DeviceID          string    `json:"device_id"`
	IdentityPublicKey string    `json:"identity_public_key"`
	Fingerprint       string    `json:"fingerprint"`
	PublicKey         string    `json:"public_key"`
	DeviceName        string    `json:"device_name"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type Registration struct {
	DeviceID          string    `json:"device_id"`
	IdentityPublicKey string    `json:"identity_public_key"`
	Fingerprint       string    `json:"fingerprint"`
	DeviceName        string    `json:"device_name"`
	RegisteredAt      time.Time `json:"registered_at"`
}

// Signal contains only short-lived ICE data. No IP payload is accepted by the
// signaling API, and the coordinator never receives WireGuard private keys.
type Signal struct {
	Seq          uint64    `json:"seq"`
	FromDeviceID string    `json:"from_device_id"`
	ToDeviceID   string    `json:"to_device_id"`
	ICEUfrag     string    `json:"ice_ufrag"`
	ICEPwd       string    `json:"ice_pwd"`
	Candidates   []string  `json:"candidates"`
	Generation   uint64    `json:"generation"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type state struct {
	Groups     map[string]*group       `json:"groups"`
	Registered map[string]Registration `json:"registered"`
	Replay     map[string]int64        `json:"replay"`
}

type group struct {
	NetworkID     string                `json:"network_id"`
	Name          string                `json:"name"`
	NetworkCIDR   string                `json:"network_cidr"`
	Revision      uint64                `json:"revision"`
	OwnerDeviceID string                `json:"owner_device_id"`
	Members       map[string]Member     `json:"members"`
	Invitations   map[string]invitation `json:"invitations"`
	Pending       map[string]pending    `json:"pending"`
	Signals       []Signal              `json:"signals"`
	NextSignalSeq uint64                `json:"next_signal_seq"`
}

type invitation struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type pending struct {
	PendingInfo
}

type apiError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func errAPI(status int, code, message string) error {
	return &apiError{Status: status, Code: code, Message: message}
}

func fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func deviceID(publicKey []byte) string { return fingerprint(publicKey)[:32] }

func (g *group) snapshot() Snapshot {
	members := make([]Member, 0, len(g.Members))
	for _, member := range g.Members {
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })
	return Snapshot{
		NetworkID:     g.NetworkID,
		Name:          g.Name,
		NetworkCIDR:   g.NetworkCIDR,
		Revision:      g.Revision,
		OwnerDeviceID: g.OwnerDeviceID,
		Members:       members,
	}
}
