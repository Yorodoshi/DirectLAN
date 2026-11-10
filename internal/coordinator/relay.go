package coordinator

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"directlan/internal/httpsrelay"
	"github.com/coder/websocket"
)

type relayFrame struct {
	at   time.Time
	data []byte
}
type relaySession struct {
	key, device string
	queue       chan relayFrame
	ws          *websocket.Conn
}
type relayHub struct {
	mu       sync.Mutex
	sessions map[string]map[string]*relaySession
	count    int
}

func (s *Server) relayAuthorized(networkID string, id identity, peerID string) bool {
	s.Store.mu.RLock()
	defer s.Store.mu.RUnlock()
	g, err := lookupGroup(&s.Store.data, networkID)
	if err != nil || requireMember(g, id) != nil || peerID == id.DeviceID {
		return false
	}
	_, ok := g.Members[peerID]
	return ok
}

func (s *Server) serveRelay(w http.ResponseWriter, r *http.Request, id identity, networkID, peerID string) {
	if !s.EnableHTTPSRelay {
		writeError(w, errAPI(http.StatusNotFound, "RELAY_DISABLED", "HTTPS relay is disabled"))
		return
	}
	if !s.relayAuthorized(networkID, id, peerID) {
		writeError(w, errAPI(http.StatusForbidden, "NOT_MEMBER", "both relay endpoints must be approved members"))
		return
	}
	if r.Header.Get("Origin") != "" {
		writeError(w, errAPI(http.StatusForbidden, "ORIGIN_DENIED", "browser origins are not accepted"))
		return
	}
	pair := []string{id.DeviceID, peerID}
	sort.Strings(pair)
	key := networkID + ":" + strings.Join(pair, ":")
	h := &s.relay
	h.mu.Lock()
	if h.sessions == nil {
		h.sessions = make(map[string]map[string]*relaySession)
	}
	if h.count >= 128 {
		h.mu.Unlock()
		writeError(w, errAPI(http.StatusTooManyRequests, "RELAY_CAPACITY", "relay capacity reached"))
		return
	}
	if h.sessions[key] == nil {
		h.sessions[key] = make(map[string]*relaySession)
	}
	if h.sessions[key][id.DeviceID] != nil {
		h.mu.Unlock()
		writeError(w, errAPI(http.StatusConflict, "RELAY_EXISTS", "relay connection already exists"))
		return
	}
	entry := &relaySession{key: key, device: id.DeviceID, queue: make(chan relayFrame, 64)}
	h.sessions[key][id.DeviceID] = entry
	h.count++
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.sessions[key], id.DeviceID)
		if len(h.sessions[key]) == 0 {
			delete(h.sessions, key)
		}
		h.count--
		h.mu.Unlock()
	}()
	// HTTP request deadlines must not terminate a long-lived upgraded socket.
	// Subsequent reads/writes and authorization are bounded by our contexts.
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	entry.ws = ws
	defer ws.CloseNow()
	ws.SetReadLimit(httpsrelay.MaxFrame)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		defer cancel()
		window := time.Now()
		used := 0
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil || typ != websocket.MessageBinary || len(data) > httpsrelay.MaxFrame {
				return
			}
			if time.Since(window) >= time.Second {
				window = time.Now()
				used = 0
			}
			used += len(data)
			if used > 8<<20 {
				return
			} // bounded bandwidth per endpoint
			h.mu.Lock()
			remote := h.sessions[key][peerID]
			if remote != nil {
				select {
				case remote.queue <- relayFrame{at: time.Now(), data: data}:
				default:
				}
			}
			h.mu.Unlock()
		}
	}()
	check := time.NewTicker(10 * time.Second)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			if !s.relayAuthorized(networkID, id, peerID) {
				return
			}
			pingCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			err := ws.Ping(pingCtx)
			stop()
			if err != nil {
				return
			}
		case frame := <-entry.queue:
			if time.Since(frame.at) > 100*time.Millisecond {
				continue
			}
			writeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			err := ws.Write(writeCtx, websocket.MessageBinary, frame.data)
			stop()
			if err != nil {
				return
			}
		}
	}
}
