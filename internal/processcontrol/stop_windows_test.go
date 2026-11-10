//go:build windows

package processcontrol

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"testing"
	"time"
)

func TestLauncherStopEvent(t *testing.T) {
	name := fmt.Sprintf(`Local\DirectLAN.Stop.test-%d`, time.Now().UnixNano())
	wide, _ := windows.UTF16PtrFromString(name)
	event, err := windows.CreateEvent(nil, 1, 0, wide)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closeWatch, err := Watch(ctx, name, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer closeWatch()
	if err := windows.SetEvent(event); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("launcher shutdown not delivered")
	}
}
