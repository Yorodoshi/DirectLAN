//go:build windows

package localipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const PipeName = `\\.\pipe\DirectLAN`
const PeerPipeName = `\\.\pipe\DirectLAN-Peer`
const maxRequest = 64 << 10

type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

type Response struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Handler func(context.Context, Request) (any, *Error)

// Serve accepts one versioned JSON line per connection. The pipe DACL admits
// only SYSTEM, Administrators and the explicitly chosen UI user SID.
func Serve(ctx context.Context, allowedUserSID string, handler Handler) error {
	return ServeNamed(ctx, PipeName, allowedUserSID, handler)
}

func ServeNamed(ctx context.Context, pipeName, allowedUserSID string, handler Handler) error {
	if handler == nil {
		return errors.New("nil IPC handler")
	}
	if allowedUserSID == "" {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return err
		}
		allowedUserSID = user.User.Sid.String()
	}
	if _, err := windows.StringToSid(allowedUserSID); err != nil {
		return fmt.Errorf("invalid allowed UI SID: %w", err)
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + allowedUserSID + ")"
	listener, err := winio.ListenPipe(pipeName, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	sem := make(chan struct{}, 16)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-sem }()
				handleConnection(ctx, conn, handler)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func handleConnection(parent context.Context, conn net.Conn, handler Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest+1)).ReadBytes('\n')
	if err != nil || len(line) > maxRequest {
		writeResponse(conn, Response{Version: 1, OK: false, Error: &Error{Code: "INVALID_REQUEST", Message: "Request exceeds limit or is incomplete"}})
		return
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(line)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Version != 1 || len(request.ID) == 0 || len(request.ID) > 64 || len(request.Method) == 0 || len(request.Method) > 64 {
		writeResponse(conn, Response{Version: 1, ID: request.ID, OK: false, Error: &Error{Code: "INVALID_REQUEST", Message: "Invalid IPC request or protocol version"}})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeResponse(conn, Response{Version: 1, ID: request.ID, OK: false, Error: &Error{Code: "INVALID_REQUEST", Message: "Trailing request data"}})
		return
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	result, apiErr := handler(ctx, request)
	response := Response{Version: 1, ID: request.ID, OK: apiErr == nil, Result: result, Error: apiErr}
	writeResponse(conn, response)
}

func writeResponse(conn net.Conn, response Response) {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > 2<<20 {
		encoded, _ = json.Marshal(Response{Version: 1, ID: response.ID, OK: false,
			Error: &Error{Code: "INTERNAL", Message: "Unable to encode IPC response"}})
	}
	encoded = append(encoded, '\n')
	_, _ = conn.Write(encoded)
}
