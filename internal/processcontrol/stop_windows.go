//go:build windows

// Package processcontrol allows the GUI launcher to request graceful shutdown
// without a console, shell, network administration endpoint or forced kill.
package processcontrol

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

func Watch(ctx context.Context, name string, stop func()) (func(), error) {
	if name == "" {
		return func() {}, nil
	}
	if !strings.HasPrefix(name, `Local\DirectLAN.Stop.`) || len(name) > 128 {
		return nil, fmt.Errorf("invalid shutdown event name")
	}
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.OpenEvent(windows.SYNCHRONIZE, false, wide)
	if err != nil {
		return nil, fmt.Errorf("open launcher shutdown event: %w", err)
	}
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer windows.CloseHandle(handle)
		for watchCtx.Err() == nil {
			state, err := windows.WaitForSingleObject(handle, 100)
			if err != nil {
				stop()
				return
			}
			if state == windows.WAIT_OBJECT_0 {
				stop()
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done }) }, nil
}
