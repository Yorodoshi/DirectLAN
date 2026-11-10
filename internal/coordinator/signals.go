package coordinator

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type postSignalRequest struct {
	ToDeviceID string    `json:"to_device_id"`
	ICEUfrag   string    `json:"ice_ufrag"`
	ICEPwd     string    `json:"ice_pwd"`
	Candidates []string  `json:"candidates"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type signalsResponse struct {
	Revision uint64   `json:"revision"`
	Members  []Member `json:"members"`
	Signals  []Signal `json:"signals"`
}

func validICEText(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validCandidate(value string) bool {
	if len(value) < len("candidate:")+1 || len(value) > 1024 || !strings.HasPrefix(value, "candidate:") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *Server) postSignal(networkID string, body []byte, id identity) (any, error) {
	var req postSignalRequest
	if err := decodeBody(body, &req); err != nil {
		return nil, err
	}
	if !validICEText(req.ICEUfrag, 4, 256) || !validICEText(req.ICEPwd, 22, 256) || len(req.Candidates) > 32 ||
		!req.ExpiresAt.After(time.Now()) || req.ExpiresAt.After(time.Now().Add(2*time.Minute)) {
		return nil, errAPI(http.StatusBadRequest, "INVALID_SIGNAL", "invalid ICE credentials, candidate count, or expiry")
	}
	totalCandidateBytes := 0
	for _, candidate := range req.Candidates {
		if !validCandidate(candidate) {
			return nil, errAPI(http.StatusBadRequest, "INVALID_CANDIDATE", "invalid ICE candidate")
		}
		totalCandidateBytes += len(candidate)
	}
	if totalCandidateBytes > 8192 {
		return nil, errAPI(http.StatusRequestEntityTooLarge, "CANDIDATES_TOO_LARGE", "ICE candidates exceed 8 KiB")
	}
	var seq uint64
	err := s.Store.mutate(func(st *state) error {
		g, err := lookupGroup(st, networkID)
		if err != nil {
			return err
		}
		if err := requireMember(g, id); err != nil {
			return err
		}
		if req.ToDeviceID == id.DeviceID {
			return errAPI(http.StatusBadRequest, "SELF_SIGNAL", "cannot signal self")
		}
		if _, found := g.Members[req.ToDeviceID]; !found {
			return errAPI(http.StatusNotFound, "MEMBER_NOT_FOUND", "destination is not a member")
		}
		kept := g.Signals[:0]
		for _, signal := range g.Signals {
			if signal.ExpiresAt.After(time.Now()) {
				kept = append(kept, signal)
			}
		}
		g.Signals = kept
		g.NextSignalSeq++
		seq = g.NextSignalSeq
		g.Signals = append(g.Signals, Signal{
			Seq: seq, FromDeviceID: id.DeviceID, ToDeviceID: req.ToDeviceID,
			ICEUfrag: req.ICEUfrag, ICEPwd: req.ICEPwd,
			Candidates: req.Candidates, Generation: req.Generation, ExpiresAt: req.ExpiresAt,
		})
		if len(g.Signals) > 64 {
			g.Signals = g.Signals[len(g.Signals)-64:]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return struct {
		Seq uint64 `json:"seq"`
	}{seq}, nil
}

func parseUintParam(query url.Values, key string) (uint64, error) {
	value := query.Get(key)
	if value == "" {
		return 0, nil
	}
	result, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errAPI(http.StatusBadRequest, "INVALID_QUERY", "invalid "+key+" query parameter")
	}
	return result, nil
}

func (s *Server) getSignals(ctx context.Context, networkID string, query url.Values, id identity) (signalsResponse, error) {
	after, err := parseUintParam(query, "after")
	if err != nil {
		return signalsResponse{}, err
	}
	afterRevision, err := parseUintParam(query, "after_revision")
	if err != nil {
		return signalsResponse{}, err
	}
	waitSeconds := 0
	if value := query.Get("wait"); value != "" {
		waitSeconds, err = strconv.Atoi(value)
		if err != nil || waitSeconds < 0 || waitSeconds > 25 {
			return signalsResponse{}, errAPI(http.StatusBadRequest, "INVALID_QUERY", "wait must be between 0 and 25 seconds")
		}
	}
	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for {
		s.Store.mu.RLock()
		g, err := lookupGroup(&s.Store.data, networkID)
		if err != nil {
			s.Store.mu.RUnlock()
			return signalsResponse{}, err
		}
		if err := requireMember(g, id); err != nil {
			s.Store.mu.RUnlock()
			return signalsResponse{}, err
		}
		snapshot := g.snapshot()
		result := signalsResponse{Revision: snapshot.Revision, Members: snapshot.Members, Signals: []Signal{}}
		for _, signal := range g.Signals {
			if signal.Seq > after && signal.ToDeviceID == id.DeviceID && signal.ExpiresAt.After(time.Now()) {
				result.Signals = append(result.Signals, signal)
			}
		}
		changed := s.Store.changed
		s.Store.mu.RUnlock()
		if len(result.Signals) != 0 || result.Revision > afterRevision || time.Now().After(deadline) || waitSeconds == 0 {
			return result, nil
		}
		remaining := time.Until(deadline)
		timer := time.NewTimer(remaining)
		select {
		case <-changed:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return signalsResponse{}, ctx.Err()
		}
		timer.Stop()
	}
}
