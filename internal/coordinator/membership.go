package coordinator

import (
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
	"time"
)

type createGroupRequest struct {
	Name        string `json:"name"`
	NetworkCIDR string `json:"network_cidr"`
	PublicKey   string `json:"public_key"`
	OverlayIP   string `json:"overlay_ip"`
	DeviceName  string `json:"device_name"`
}

func (s *Server) createGroup(body []byte, id identity) (Snapshot, error) {
	var req createGroupRequest
	if err := decodeBody(body, &req); err != nil {
		return Snapshot{}, err
	}
	if !validLabel(req.Name, 64) || !validWGPublicKey(req.PublicKey) {
		return Snapshot{}, errAPI(http.StatusBadRequest, "INVALID_GROUP", "invalid group name or WireGuard public key")
	}
	if _, ok := validNetworkCIDR(req.NetworkCIDR); !ok || !validOverlayIP(req.NetworkCIDR, req.OverlayIP) {
		return Snapshot{}, errAPI(http.StatusBadRequest, "INVALID_OVERLAY", "network_cidr must be a private IPv4 /16 through /28 and overlay_ip must be a usable host")
	}
	if req.DeviceName == "" {
		req.DeviceName = "Device"
	}
	if !validLabel(req.DeviceName, 64) {
		return Snapshot{}, errAPI(http.StatusBadRequest, "INVALID_DEVICE_NAME", "invalid device name")
	}
	networkID, err := randomToken(16)
	if err != nil {
		return Snapshot{}, err
	}
	var result Snapshot
	err = s.Store.mutate(func(st *state) error {
		if len(st.Groups) >= 128 {
			return errAPI(http.StatusTooManyRequests, "CAPACITY", "coordinator group limit reached")
		}
		if _, exists := st.Groups[networkID]; exists {
			return errAPI(http.StatusConflict, "RETRY", "group identifier collision")
		}
		if _, err := ensureRegistration(st, id, req.DeviceName); err != nil {
			return err
		}
		member := Member{
			DeviceID: id.DeviceID, IdentityPublicKey: id.EncodedKey, PublicKey: req.PublicKey,
			OverlayIP: req.OverlayIP, DeviceName: req.DeviceName, JoinedAt: time.Now().UTC(),
		}
		g := &group{
			NetworkID: networkID, Name: req.Name, NetworkCIDR: req.NetworkCIDR,
			Revision: 1, OwnerDeviceID: id.DeviceID,
			Members:     map[string]Member{id.DeviceID: member},
			Invitations: make(map[string]invitation), Pending: make(map[string]pending),
		}
		st.Groups[networkID] = g
		result = g.snapshot()
		return nil
	})
	return result, err
}

func (s *Server) snapshot(networkID string, id identity) (Snapshot, error) {
	s.Store.mu.RLock()
	defer s.Store.mu.RUnlock()
	g, err := lookupGroup(&s.Store.data, networkID)
	if err != nil {
		return Snapshot{}, err
	}
	if err := requireMember(g, id); err != nil {
		return Snapshot{}, err
	}
	return g.snapshot(), nil
}

func (s *Server) invite(networkID string, body []byte, id identity) (any, error) {
	if len(body) != 0 {
		var empty struct{}
		if err := decodeBody(body, &empty); err != nil {
			return nil, err
		}
	}
	token, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	err = s.Store.mutate(func(st *state) error {
		g, err := lookupGroup(st, networkID)
		if err != nil {
			return err
		}
		if err := requireOwner(g, id); err != nil {
			return err
		}
		if len(g.Members) >= 10 {
			return errAPI(http.StatusConflict, "GROUP_FULL", "group has reached its 10-device limit")
		}
		for hash, invite := range g.Invitations {
			if !invite.ExpiresAt.After(time.Now()) {
				delete(g.Invitations, hash)
			}
		}
		if len(g.Invitations) >= 20 {
			return errAPI(http.StatusTooManyRequests, "INVITE_LIMIT", "too many active invitations")
		}
		g.Invitations[tokenHash(token)] = invitation{ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return struct {
		Invitation string    `json:"invitation"`
		NetworkID  string    `json:"network_id"`
		ExpiresAt  time.Time `json:"expires_at"`
	}{token, networkID, expiresAt}, nil
}

type joinRequest struct {
	Invitation string `json:"invitation"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
}

func (s *Server) join(body []byte, id identity) (any, error) {
	var req joinRequest
	if err := decodeBody(body, &req); err != nil {
		return nil, err
	}
	token, decodeErr := base64.RawURLEncoding.DecodeString(req.Invitation)
	if decodeErr != nil || len(token) != 24 || !validWGPublicKey(req.PublicKey) || !validLabel(req.DeviceName, 64) {
		return nil, errAPI(http.StatusBadRequest, "INVALID_JOIN", "invalid invitation, key, or device name")
	}
	pendingID, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	var result any
	err = s.Store.mutate(func(st *state) error {
		var g *group
		var networkID string
		hash := tokenHash(req.Invitation)
		for id, candidate := range st.Groups {
			if _, found := candidate.Invitations[hash]; found {
				g, networkID = candidate, id
				break
			}
		}
		if g == nil {
			return errAPI(http.StatusNotFound, "INVITATION_NOT_FOUND", "invitation is invalid or already used")
		}
		invite := g.Invitations[hash]
		if !invite.ExpiresAt.After(time.Now()) {
			return errAPI(http.StatusGone, "INVITATION_EXPIRED", "invitation has expired")
		}
		if _, exists := g.Members[id.DeviceID]; exists {
			return errAPI(http.StatusConflict, "ALREADY_MEMBER", "device is already a member")
		}
		for _, p := range g.Pending {
			if p.DeviceID == id.DeviceID && p.ExpiresAt.After(time.Now()) {
				return errAPI(http.StatusConflict, "JOIN_PENDING", "device already has a pending request")
			}
		}
		for pid, p := range g.Pending {
			if !p.ExpiresAt.After(time.Now()) {
				delete(g.Pending, pid)
			}
		}
		if len(g.Members)+len(g.Pending) >= 10 {
			return errAPI(http.StatusConflict, "GROUP_FULL", "group has reached its 10-device limit")
		}
		for _, member := range g.Members {
			if member.PublicKey == req.PublicKey {
				return errAPI(http.StatusConflict, "KEY_IN_USE", "WireGuard key is already in use")
			}
		}
		if _, err := ensureRegistration(st, id, req.DeviceName); err != nil {
			return err
		}
		delete(g.Invitations, hash) // consume even while owner approval is pending
		expiresAt := time.Now().UTC().Add(10 * time.Minute)
		g.Pending[pendingID] = pending{PendingInfo: PendingInfo{
			PendingID: pendingID, DeviceID: id.DeviceID,
			IdentityPublicKey: id.EncodedKey, Fingerprint: id.Fingerprint,
			PublicKey: req.PublicKey, DeviceName: req.DeviceName, ExpiresAt: expiresAt,
		}}
		owner := g.Members[g.OwnerDeviceID]
		result = struct {
			PendingID              string    `json:"pending_id"`
			NetworkID              string    `json:"network_id"`
			NetworkCIDR            string    `json:"network_cidr"`
			OwnerIdentityPublicKey string    `json:"owner_identity_public_key"`
			OwnerFingerprint       string    `json:"owner_fingerprint"`
			ExpiresAt              time.Time `json:"expires_at"`
		}{pendingID, networkID, g.NetworkCIDR, owner.IdentityPublicKey,
			fingerprintOfEncoded(owner.IdentityPublicKey), expiresAt}
		return nil
	})
	return result, err
}

func fingerprintOfEncoded(encoded string) string {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return fingerprint(key)
}

func (s *Server) listPending(networkID string, id identity) (any, error) {
	s.Store.mu.RLock()
	defer s.Store.mu.RUnlock()
	g, err := lookupGroup(&s.Store.data, networkID)
	if err != nil {
		return nil, err
	}
	if err := requireOwner(g, id); err != nil {
		return nil, err
	}
	items := make([]PendingInfo, 0, len(g.Pending))
	for _, p := range g.Pending {
		if p.ExpiresAt.After(time.Now()) {
			items = append(items, p.PendingInfo)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].PendingID < items[j].PendingID })
	return struct {
		Pending []PendingInfo `json:"pending"`
	}{items}, nil
}

type approveRequest struct {
	Fingerprint string `json:"fingerprint"`
	OverlayIP   string `json:"overlay_ip"`
}

func (s *Server) approve(networkID, pendingID string, body []byte, id identity) (Snapshot, error) {
	var req approveRequest
	if err := decodeBody(body, &req); err != nil {
		return Snapshot{}, err
	}
	var result Snapshot
	err := s.Store.mutate(func(st *state) error {
		g, err := lookupGroup(st, networkID)
		if err != nil {
			return err
		}
		if err := requireOwner(g, id); err != nil {
			return err
		}
		p, found := g.Pending[pendingID]
		if !found || !p.ExpiresAt.After(time.Now()) {
			return errAPI(http.StatusNotFound, "PENDING_NOT_FOUND", "pending request is missing or expired")
		}
		if !strings.EqualFold(req.Fingerprint, p.Fingerprint) {
			return errAPI(http.StatusConflict, "FINGERPRINT_MISMATCH", "confirmed fingerprint does not match the requesting identity")
		}
		if !validOverlayIP(g.NetworkCIDR, req.OverlayIP) {
			return errAPI(http.StatusBadRequest, "INVALID_OVERLAY", "overlay_ip is outside the usable network range")
		}
		if len(g.Members) >= 10 {
			return errAPI(http.StatusConflict, "GROUP_FULL", "group has reached its 10-device limit")
		}
		for _, member := range g.Members {
			if member.OverlayIP == req.OverlayIP || member.PublicKey == p.PublicKey || member.IdentityPublicKey == p.IdentityPublicKey {
				return errAPI(http.StatusConflict, "DUPLICATE_MEMBER", "overlay IP or public key is already in use")
			}
		}
		g.Members[p.DeviceID] = Member{
			DeviceID: p.DeviceID, IdentityPublicKey: p.IdentityPublicKey,
			PublicKey: p.PublicKey, OverlayIP: req.OverlayIP,
			DeviceName: p.DeviceName, JoinedAt: time.Now().UTC(),
		}
		delete(g.Pending, pendingID)
		g.Revision++
		result = g.snapshot()
		return nil
	})
	return result, err
}

func (s *Server) revoke(networkID, targetID string, id identity) (Snapshot, error) {
	var result Snapshot
	err := s.Store.mutate(func(st *state) error {
		g, err := lookupGroup(st, networkID)
		if err != nil {
			return err
		}
		if err := requireOwner(g, id); err != nil {
			return err
		}
		if targetID == g.OwnerDeviceID {
			return errAPI(http.StatusConflict, "OWNER_REVOKE", "owner cannot revoke itself")
		}
		if _, found := g.Members[targetID]; !found {
			return errAPI(http.StatusNotFound, "MEMBER_NOT_FOUND", "member does not exist")
		}
		delete(g.Members, targetID)
		kept := g.Signals[:0]
		for _, signal := range g.Signals {
			if signal.FromDeviceID != targetID && signal.ToDeviceID != targetID {
				kept = append(kept, signal)
			}
		}
		g.Signals = kept
		g.Revision++
		result = g.snapshot()
		return nil
	})
	return result, err
}
