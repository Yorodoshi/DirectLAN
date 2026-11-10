//go:build !windows

package processcontrol

import (
	"context"
	"errors"
)

func Watch(_ context.Context, name string, _ func()) (func(), error) {
	if name != "" {
		return nil, errors.New("named shutdown events require Windows")
	}
	return func() {}, nil
}
