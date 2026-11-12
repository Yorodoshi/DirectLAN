//go:build windows

package mesh

import (
	"context"
	"time"

	"directlan/internal/tunnel"
)

// Admission replies must not wait for discovery or the five-second OS probe.
// Re-snapshot after every event so replaced tunnels cannot apply stale queues.
func (n *node) controlLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		n.mu.Lock()
		wg := n.wg
		n.mu.Unlock()
		var messages <-chan tunnel.ControlMessage
		if wg != nil {
			messages = wg.ControlMessages()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.controlWake:
		case message := <-messages:
			n.handleControl(wg, message)
		}
	}
}
