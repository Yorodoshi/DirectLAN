package coordinator

import (
	"net/http"
	"time"
)

type registerRequest struct {
	DeviceName string `json:"device_name"`
}

func ensureRegistration(st *state, id identity, name string) (Registration, error) {
	if st.Registered == nil {
		st.Registered = make(map[string]Registration)
	}
	if previous, found := st.Registered[id.DeviceID]; found {
		if previous.IdentityPublicKey != id.EncodedKey {
			return Registration{}, errAPI(http.StatusConflict, "IDENTITY_COLLISION", "device identifier collision")
		}
		return previous, nil
	}
	if len(st.Registered) >= 4096 {
		return Registration{}, errAPI(http.StatusTooManyRequests, "CAPACITY", "coordinator registration limit reached")
	}
	registration := Registration{
		DeviceID: id.DeviceID, IdentityPublicKey: id.EncodedKey,
		Fingerprint: id.Fingerprint, DeviceName: name, RegisteredAt: time.Now().UTC(),
	}
	st.Registered[id.DeviceID] = registration
	return registration, nil
}

func (s *Server) register(body []byte, id identity) (Registration, error) {
	var req registerRequest
	if err := decodeBody(body, &req); err != nil {
		return Registration{}, err
	}
	if !validLabel(req.DeviceName, 64) {
		return Registration{}, errAPI(http.StatusBadRequest, "INVALID_DEVICE_NAME", "invalid device name")
	}
	var result Registration
	err := s.Store.mutate(func(st *state) error {
		var err error
		result, err = ensureRegistration(st, id, req.DeviceName)
		return err
	})
	return result, err
}

func (s *Server) heartbeat(networkID string, id identity) (any, error) {
	snapshot, err := s.snapshot(networkID, id)
	if err != nil {
		return nil, err
	}
	return struct {
		NetworkID  string    `json:"network_id"`
		Revision   uint64    `json:"revision"`
		ServerTime time.Time `json:"server_time"`
	}{snapshot.NetworkID, snapshot.Revision, time.Now().UTC()}, nil
}
