//go:build windows

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"directlan/internal/client"
	"directlan/internal/coordinator"
	"directlan/internal/identity"
	"directlan/internal/localipc"
	"directlan/internal/platform"
)

type Config struct {
	CoordinatorURL string
	IdentityPath   string
	AllowedUISID   string
	DeviceName     string
	DevHTTP        bool
	Transport      string
	Padding        bool
	STUNURLs       []string
	CAPath         string
}

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type PeerStatus struct {
	DeviceID    string  `json:"device_id"`
	Name        string  `json:"name"`
	OverlayIP   string  `json:"overlay_ip,omitempty"`
	Approved    bool    `json:"approved"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	State       string  `json:"state"`
	Egress      string  `json:"egress"`
	RTTMs       float64 `json:"rtt_ms,omitempty"`
	Transport   string  `json:"transport,omitempty"`
}

type ConnectionStatus struct {
	State   string            `json:"state"`
	Egress  string            `json:"egress"`
	Adapter *platform.Adapter `json:"adapter,omitempty"`
	RTTMs   float64           `json:"rtt_ms,omitempty"`
}

type Status struct {
	Group      *coordinator.Snapshot `json:"group,omitempty"`
	VirtualIP  string                `json:"virtual_ip,omitempty"`
	Members    []PeerStatus          `json:"members"`
	Connection ConnectionStatus      `json:"connection"`
	Adapter    *platform.Adapter     `json:"adapter,omitempty"`
	Events     []Event               `json:"events"`
}

type Service struct {
	mu          sync.RWMutex
	opMu        sync.Mutex
	cfg         Config
	identity    identity.State
	api         *client.Client
	snapshot    *coordinator.Snapshot
	pending     []coordinator.PendingInfo
	adapter     *platform.Adapter
	lastContact time.Time
	events      []Event
	peerStatus  map[string]PeerStatus
	network     networkState
}

func New(cfg Config) (*Service, error) {
	if cfg.CoordinatorURL == "" || cfg.IdentityPath == "" {
		return nil, errors.New("coordinator URL and identity path are required")
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName, _ = os.Hostname()
	}
	if cfg.DeviceName == "" || len(cfg.DeviceName) > 64 {
		return nil, errors.New("invalid device name")
	}
	state, err := identity.LoadOrCreate(cfg.IdentityPath)
	if err != nil {
		return nil, err
	}
	api, err := client.New(cfg.CoordinatorURL, ed25519.PrivateKey(state.IdentityPrivate), cfg.DevHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.CAPath != "" {
		pem, readErr := os.ReadFile(cfg.CAPath)
		if readErr != nil {
			return nil, readErr
		}
		if err := api.SetTrustedCA(pem); err != nil {
			return nil, err
		}
	}
	if cfg.Transport == "" {
		cfg.Transport = "https"
	}
	if cfg.Transport != "auto" && cfg.Transport != "direct" && cfg.Transport != "https" {
		return nil, errors.New("transport must be auto, direct or https")
	}
	s := &Service{cfg: cfg, identity: state, api: api, peerStatus: make(map[string]PeerStatus)}
	s.eventLocked("info", "Служба запущена; прямой канал требует проверки выхода и WireGuard")
	return s, nil
}

func (s *Service) Run(ctx context.Context) error {
	defer s.stopNetwork()
	go s.refreshLoop(ctx)
	go s.signalLoop(ctx)
	return localipc.Serve(ctx, s.cfg.AllowedUISID, s.Handle)
}

func (s *Service) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	s.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh(ctx)
		}
	}
}

func (s *Service) refresh(ctx context.Context) {
	s.mu.RLock()
	networkID := s.identity.NetworkID
	selfID := ownDeviceID(s.identity)
	s.mu.RUnlock()
	if networkID == "" {
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	snapshot, err := s.api.Group(callCtx, networkID)
	if err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "NOT_MEMBER" {
			s.stopNetwork()
			s.mu.Lock()
			s.snapshot = nil
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		expired := !s.lastContact.IsZero() && time.Since(s.lastContact) > 15*time.Minute
		if expired {
			s.eventLocked("error", "Авторизация истекла: координатор недоступен более 15 минут")
			// Active peer transports are stopped by the tunnel manager.
		}
		s.mu.Unlock()
		if expired {
			s.stopNetwork()
		}
		return
	}
	var pending []coordinator.PendingInfo
	if snapshot.OwnerDeviceID == selfID {
		pending, _ = s.api.Pending(callCtx, networkID)
	}
	s.mu.Lock()
	if s.identity.NetworkID != networkID {
		s.mu.Unlock()
		return
	}
	if snapshot.Revision < s.identity.Revision {
		s.mu.Unlock()
		return
	}
	if err := s.acceptSnapshotLocked(snapshot); err != nil {
		s.eventLocked("error", err.Error())
		s.mu.Unlock()
		s.stopNetwork()
		return
	}
	s.lastContact = time.Now()
	if snapshot.OwnerDeviceID == ownDeviceID(s.identity) {
		s.pending = pending
	}
	s.mu.Unlock()
	s.ensureNetwork(ctx)
}

func (s *Service) acceptSnapshotLocked(snapshot coordinator.Snapshot) error {
	if snapshot.NetworkID != s.identity.NetworkID {
		return errors.New("координатор вернул другую группу")
	}
	if snapshot.Revision < s.identity.Revision {
		return errors.New("координатор вернул устаревшую revision")
	}
	selfID := ownDeviceID(s.identity)
	selfWG, err := s.identity.WireGuardPublicBase64()
	if err != nil {
		return err
	}
	selfFound := false
	ownerFound := false
	pins := make(map[string]string, len(s.identity.MemberPins)+len(snapshot.Members))
	for id, pin := range s.identity.MemberPins {
		pins[id] = pin
	}
	newPin := false
	for _, member := range snapshot.Members {
		pin := sha256.Sum256([]byte(member.IdentityPublicKey + "\n" + member.PublicKey + "\n" + member.OverlayIP))
		pinText := hex.EncodeToString(pin[:])
		if previous, ok := pins[member.DeviceID]; ok && previous != pinText {
			return errors.New("изменился закреплённый ключ или адрес участника; требуется новое подтверждение")
		}
		if pins[member.DeviceID] == "" {
			pins[member.DeviceID] = pinText
			newPin = true
		}
		if member.DeviceID == selfID {
			selfFound = member.PublicKey == selfWG && member.IdentityPublicKey == base64.RawURLEncoding.EncodeToString(s.identity.IdentityPublic())
		}
		if member.DeviceID == snapshot.OwnerDeviceID {
			public, decodeErr := base64.RawURLEncoding.DecodeString(member.IdentityPublicKey)
			if decodeErr == nil {
				sum := sha256.Sum256(public)
				ownerFound = s.identity.OwnerFingerprint == "" || s.identity.OwnerFingerprint == hex.EncodeToString(sum[:])
			}
		}
	}
	if !selfFound || !ownerFound {
		return errors.New("несовпадение подтверждённых ключей группы")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	hashText := hex.EncodeToString(hash[:])
	if snapshot.Revision == s.identity.Revision && s.identity.SnapshotHash != "" && s.identity.SnapshotHash != hashText {
		return errors.New("членство изменилось без новой revision")
	}
	if snapshot.Revision > s.identity.Revision || s.identity.SnapshotHash == "" || newPin {
		updated := s.identity
		updated.Revision = snapshot.Revision
		updated.SnapshotHash = hashText
		updated.MemberPins = pins
		if err := identity.Save(s.cfg.IdentityPath, updated); err != nil {
			return fmt.Errorf("не удалось сохранить revision: %w", err)
		}
		s.identity = updated
	}
	copy := snapshot
	s.snapshot = &copy
	return nil
}

func ownDeviceID(state identity.State) string {
	sum := sha256.Sum256(state.IdentityPublic())
	return hex.EncodeToString(sum[:16])
}

func (s *Service) eventLocked(level, message string) {
	s.events = append([]Event{{Timestamp: time.Now(), Level: level, Message: message}}, s.events...)
	if len(s.events) > 50 {
		s.events = s.events[:50]
	}
}

func bad(code, message, action string) *localipc.Error {
	return &localipc.Error{Code: code, Message: message, Action: action}
}

func decodeParams(raw json.RawMessage, target any) *localipc.Error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return bad("INVALID_PARAMS", "Неверные параметры запроса", "Обновите интерфейс DirectLAN")
	}
	return nil
}

func (s *Service) Handle(ctx context.Context, req localipc.Request) (any, *localipc.Error) {
	if req.Method != "status" && req.Method != "adapter.list" && req.Method != "diagnostics.export" && req.Method != "connection.check" {
		s.opMu.Lock()
		defer s.opMu.Unlock()
	}
	switch req.Method {
	case "status":
		return s.status(), nil
	case "adapter.list":
		adapters, err := platform.PhysicalCandidates()
		if err != nil {
			return nil, bad("ADAPTER_LIST_FAILED", err.Error(), "Проверьте сетевые интерфейсы Windows")
		}
		return adapters, nil
	case "adapter.select":
		var p struct {
			ID string `json:"id"`
		}
		if e := decodeParams(req.Params, &p); e != nil {
			return nil, e
		}
		return s.selectAdapter(p.ID)
	case "group.create":
		var p struct {
			Name string `json:"name"`
		}
		if e := decodeParams(req.Params, &p); e != nil {
			return nil, e
		}
		return s.createGroup(ctx, p.Name)
	case "invite.create":
		return s.createInvitation(ctx)
	case "invitation.join":
		var p struct {
			Token string `json:"token"`
		}
		if e := decodeParams(req.Params, &p); e != nil {
			return nil, e
		}
		return s.join(ctx, p.Token)
	case "member.approve":
		var p struct {
			DeviceID    string `json:"device_id"`
			Fingerprint string `json:"fingerprint"`
		}
		if e := decodeParams(req.Params, &p); e != nil {
			return nil, e
		}
		return s.approve(ctx, p.DeviceID, p.Fingerprint)
	case "member.revoke":
		var p struct {
			DeviceID string `json:"device_id"`
		}
		if e := decodeParams(req.Params, &p); e != nil {
			return nil, e
		}
		return s.revoke(ctx, p.DeviceID)
	case "connection.check":
		var p struct {
			DeviceID string `json:"device_id"`
		}
		if e := decodeParams(req.Params, &p); e != nil {
			return nil, e
		}
		return s.checkConnection(p.DeviceID)
	case "diagnostics.export":
		return s.diagnostics(), nil
	default:
		return nil, bad("UNKNOWN_METHOD", "Неизвестное действие", "Обновите интерфейс DirectLAN")
	}
}

func (s *Service) status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Status{Members: make([]PeerStatus, 0), Connection: ConnectionStatus{State: "Offline", Egress: "Unknown"}, Events: append([]Event(nil), s.events...)}
	if s.adapter != nil {
		copy := *s.adapter
		result.Adapter = &copy
		result.Connection.Adapter = &copy
	}
	if s.snapshot == nil {
		if s.identity.NetworkID != "" {
			result.Connection.State = "Discovering"
		}
		return result
	}
	copy := *s.snapshot
	result.Group = &copy
	for _, member := range copy.Members {
		if member.DeviceID == ownDeviceID(s.identity) {
			result.VirtualIP = member.OverlayIP
		}
		public, _ := base64.RawURLEncoding.DecodeString(member.IdentityPublicKey)
		sum := sha256.Sum256(public)
		peer := PeerStatus{DeviceID: member.DeviceID, Name: member.DeviceName, OverlayIP: member.OverlayIP,
			Approved: true, Fingerprint: hex.EncodeToString(sum[:]), State: "Offline", Egress: "Unknown"}
		if link, ok := s.peerStatus[member.DeviceID]; ok {
			peer.State = link.State
			peer.RTTMs = link.RTTMs
			peer.Transport = link.Transport
		}
		result.Members = append(result.Members, peer)
	}
	for _, pending := range s.pending {
		result.Members = append(result.Members, PeerStatus{DeviceID: pending.DeviceID, Name: pending.DeviceName,
			Approved: false, Fingerprint: pending.Fingerprint, State: "Discovering", Egress: "Unknown"})
	}
	if s.adapter == nil {
		result.Connection.State = "Blocked"
	} else {
		result.Connection.State = "Discovering"
	}
	for _, peer := range result.Members {
		if peer.State == "Direct" || peer.State == "Relay" {
			result.Connection.State = peer.State
			result.Connection.RTTMs = peer.RTTMs
			break
		}
		if peer.State == "Blocked" {
			result.Connection.State = "Blocked"
		}
	}
	if !s.lastContact.IsZero() && time.Since(s.lastContact) > 15*time.Minute {
		result.Connection.State = "Blocked"
	}
	return result
}

func (s *Service) selectAdapter(id string) (any, *localipc.Error) {
	adapters, err := platform.PhysicalCandidates()
	if err != nil {
		return nil, bad("ADAPTER_LIST_FAILED", err.Error(), "Проверьте сетевые интерфейсы Windows")
	}
	for _, adapter := range adapters {
		if adapter.ID == id {
			s.mu.Lock()
			updated := s.identity
			updated.AdapterID = id
			if err := identity.Save(s.cfg.IdentityPath, updated); err != nil {
				s.mu.Unlock()
				return nil, bad("STATE_SAVE_FAILED", err.Error(), "Проверьте доступ к каталогу службы")
			}
			s.identity = updated
			s.adapter = &adapter
			s.eventLocked("info", "Выбран интерфейс "+adapter.Name)
			s.mu.Unlock()
			return adapter, nil
		}
	}
	return nil, bad("ADAPTER_UNAVAILABLE", "Выбранный физический интерфейс недоступен", "Выберите другой Ethernet или Wi-Fi")
}

func (s *Service) createGroup(ctx context.Context, name string) (any, *localipc.Error) {
	if name == "" || len(name) > 64 {
		return nil, bad("INVALID_NAME", "Название группы должно содержать от 1 до 64 символов", "Введите другое название")
	}
	s.mu.RLock()
	existing := s.identity.NetworkID
	wgPublic, keyErr := s.identity.WireGuardPublicBase64()
	s.mu.RUnlock()
	if existing != "" {
		return nil, bad("ALREADY_IN_GROUP", "Устройство уже состоит в группе", "Используйте существующую группу")
	}
	if keyErr != nil {
		return nil, bad("KEY_ERROR", keyErr.Error(), "Перезапустите службу")
	}
	cidr, ip, err := selectOverlayPrefix()
	if err != nil {
		return nil, bad("ROUTE_CONFLICT", err.Error(), "Устраните конфликт маршрутов")
	}
	snapshot, err := s.api.CreateGroup(ctx, name, cidr, wgPublic, ip, s.cfg.DeviceName)
	if err != nil {
		return nil, toIPCError(err)
	}
	s.mu.Lock()
	updated := s.identity
	updated.NetworkID = snapshot.NetworkID
	if err := identity.Save(s.cfg.IdentityPath, updated); err != nil {
		s.mu.Unlock()
		return nil, bad("STATE_SAVE_FAILED", err.Error(), "Сохраните идентификатор группы вручную и проверьте диск")
	}
	s.identity = updated
	if err := s.acceptSnapshotLocked(snapshot); err != nil {
		s.mu.Unlock()
		return nil, bad("SNAPSHOT_REJECTED", err.Error(), "Проверьте ключи и revision")
	}
	s.lastContact = time.Now()
	s.eventLocked("info", "Группа создана")
	s.mu.Unlock()
	return snapshot, nil
}

func selectOverlayPrefix() (string, string, error) {
	for tries := 0; tries < 64; tries++ {
		var random [3]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", "", err
		}
		first, second, third := 10, int(random[1]), int(random[2])
		switch random[0] % 3 {
		case 1:
			first = 172
			second = 16 + int(random[1])%16
		case 2:
			first = 192
			second = 168
		}
		cidr := fmt.Sprintf("%d.%d.%d.0/24", first, second, third)
		_, network, _ := net.ParseCIDR(cidr)
		conflict, _, err := platform.RouteConflict(network, 0)
		if err != nil {
			return "", "", err
		}
		if !conflict {
			return cidr, fmt.Sprintf("%d.%d.%d.1", first, second, third), nil
		}
	}
	return "", "", errors.New("не найден свободный частный IPv4 диапазон")
}

func (s *Service) createInvitation(ctx context.Context) (any, *localipc.Error) {
	s.mu.RLock()
	id := s.identity.NetworkID
	s.mu.RUnlock()
	if id == "" {
		return nil, bad("NO_GROUP", "Сначала создайте группу", "Создайте группу")
	}
	inv, err := s.api.CreateInvitation(ctx, id)
	if err != nil {
		return nil, toIPCError(err)
	}
	return map[string]any{"token": inv.Invitation, "expires_at": inv.ExpiresAt}, nil
}

func (s *Service) join(ctx context.Context, token string) (any, *localipc.Error) {
	if token == "" || len(token) > 256 {
		return nil, bad("INVALID_INVITATION", "Неверный код приглашения", "Запросите новый код")
	}
	s.mu.RLock()
	existing := s.identity.NetworkID
	wgPublic, keyErr := s.identity.WireGuardPublicBase64()
	s.mu.RUnlock()
	if existing != "" {
		return nil, bad("ALREADY_IN_GROUP", "Устройство уже состоит в группе", "Используйте существующую группу")
	}
	if keyErr != nil {
		return nil, bad("KEY_ERROR", keyErr.Error(), "Перезапустите службу")
	}
	join, err := s.api.Join(ctx, token, wgPublic, s.cfg.DeviceName)
	if err != nil {
		return nil, toIPCError(err)
	}
	_, network, err := net.ParseCIDR(join.NetworkCIDR)
	if err != nil {
		return nil, bad("INVALID_OVERLAY", "Координатор вернул неверную подсеть", "Не подтверждайте это приглашение")
	}
	conflict, route, err := platform.RouteConflict(network, 0)
	if err != nil {
		return nil, bad("ROUTE_CHECK_FAILED", err.Error(), "Проверьте таблицу маршрутов")
	}
	if conflict {
		return nil, bad("ROUTE_CONFLICT", "Виртуальная сеть пересекается с локальным маршрутом "+route, "Попросите владельца выбрать другую группу")
	}
	s.mu.Lock()
	updated := s.identity
	updated.NetworkID = join.NetworkID
	updated.OwnerFingerprint = join.OwnerFingerprint
	if err := identity.Save(s.cfg.IdentityPath, updated); err != nil {
		s.mu.Unlock()
		return nil, bad("STATE_SAVE_FAILED", err.Error(), "Проверьте каталог службы")
	}
	s.identity = updated
	s.eventLocked("info", "Запрос на вступление отправлен; ожидается сверка отпечатка владельца")
	s.mu.Unlock()
	return join, nil
}

func (s *Service) approve(ctx context.Context, deviceID, fingerprint string) (any, *localipc.Error) {
	s.mu.RLock()
	id := s.identity.NetworkID
	snapshot := s.snapshot
	s.mu.RUnlock()
	if id == "" || snapshot == nil {
		return nil, bad("NO_GROUP", "Группа недоступна", "Обновите состояние")
	}
	pending, err := s.api.Pending(ctx, id)
	if err != nil {
		return nil, toIPCError(err)
	}
	var chosen *coordinator.PendingInfo
	for i := range pending {
		if pending[i].DeviceID == deviceID && pending[i].Fingerprint == fingerprint {
			chosen = &pending[i]
			break
		}
	}
	if chosen == nil {
		return nil, bad("FINGERPRINT_MISMATCH", "Отпечаток не совпадает с запросом", "Сверьте отпечаток заново")
	}
	ip, err := nextOverlayIP(*snapshot)
	if err != nil {
		return nil, bad("GROUP_FULL", err.Error(), "Удалите неиспользуемое устройство")
	}
	updated, err := s.api.Approve(ctx, id, chosen.PendingID, fingerprint, ip)
	if err != nil {
		return nil, toIPCError(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.acceptSnapshotLocked(updated); err != nil {
		return nil, bad("SNAPSHOT_REJECTED", err.Error(), "Проверьте revision")
	}
	s.pending = nil
	s.lastContact = time.Now()
	s.eventLocked("info", "Устройство подтверждено")
	return updated, nil
}

func nextOverlayIP(snapshot coordinator.Snapshot) (string, error) {
	_, network, err := net.ParseCIDR(snapshot.NetworkCIDR)
	if err != nil {
		return "", err
	}
	used := make(map[string]bool)
	for _, m := range snapshot.Members {
		used[m.OverlayIP] = true
	}
	base := network.IP.To4()
	if base == nil {
		return "", errors.New("IPv4 expected")
	}
	for host := 2; host < 255; host++ {
		ip := net.IPv4(base[0], base[1], base[2], byte(host)).String()
		if network.Contains(net.ParseIP(ip)) && !used[ip] {
			return ip, nil
		}
	}
	return "", errors.New("нет свободного виртуального IP")
}

func (s *Service) revoke(ctx context.Context, deviceID string) (any, *localipc.Error) {
	s.mu.RLock()
	id := s.identity.NetworkID
	selfID := ownDeviceID(s.identity)
	s.mu.RUnlock()
	if id == "" || deviceID == selfID {
		return nil, bad("INVALID_DEVICE", "Нельзя удалить это устройство", "Выберите другого участника")
	}
	updated, err := s.api.Revoke(ctx, id, deviceID)
	if err != nil {
		return nil, toIPCError(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.acceptSnapshotLocked(updated); err != nil {
		return nil, bad("SNAPSHOT_REJECTED", err.Error(), "Проверьте revision")
	}
	s.lastContact = time.Now()
	s.eventLocked("info", "Доступ участника отозван")
	return updated, nil
}

func (s *Service) diagnostics() any {
	status := s.status()
	// No privileged path writes; the UI saves this report as the current user.
	// Detailed event messages can contain socket addresses, so export counts.
	levels := make(map[string]int)
	for _, event := range status.Events {
		levels[event.Level]++
	}
	return map[string]any{"timestamp": time.Now().UTC(), "connection": map[string]string{"state": status.Connection.State, "egress": status.Connection.Egress},
		"member_count": len(status.Members), "group_present": status.Group != nil,
		"event_counts": levels, "transport_profile": s.cfg.Transport, "padding": s.cfg.Padding}
}

func toIPCError(err error) *localipc.Error {
	var api *client.APIError
	if errors.As(err, &api) {
		return bad(api.Code, api.Message, "Проверьте координатор и повторите действие")
	}
	return bad("COORDINATOR_UNAVAILABLE", err.Error(), "Проверьте адрес, TLS и доступность координатора")
}
