//go:build !windows

package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// The lock file and flock match stack-profile's native FileLockGuard.
func withRefreshLock(ctx context.Context, path string, run func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path is inside the caller's profile directory
	if err != nil {
		return fmt.Errorf("auth: open refresh lock: %w", err)
	}
	defer f.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("auth: acquire refresh lock: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	return run()
}
