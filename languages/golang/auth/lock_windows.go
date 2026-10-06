//go:build windows

package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Lock the same first 2^64-1 bytes stack-profile's Windows FileLockGuard
// locks. OVERLAPPED offset zero makes the range identical.
func withRefreshLock(ctx context.Context, path string, run func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path is inside the caller's profile directory
	if err != nil {
		return fmt.Errorf("auth: open refresh lock: %w", err)
	}
	defer f.Close()
	h := windows.Handle(f.Fd())
	var overlap windows.Overlapped
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xffffffff, 0xffffffff, &overlap)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("auth: acquire refresh lock: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer func() { _ = windows.UnlockFileEx(h, 0, 0xffffffff, 0xffffffff, &overlap) }()
	return run()
}
