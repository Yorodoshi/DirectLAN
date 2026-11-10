//go:build windows

package tunnel

import (
	"directlan/internal/platform"
	"fmt"
)

func (t *Tunnel) CheckRoutes() error {
	t.mu.Lock()
	running, index, prefix := t.running, t.ifIndex, t.groupCIDR
	t.mu.Unlock()
	if !running {
		return ErrNotStarted
	}
	conflict, route, err := platform.RouteConflict(prefix, index)
	if err != nil {
		return err
	}
	if conflict {
		return fmt.Errorf("%w: %s", ErrRouteConflict, route)
	}
	return nil
}
