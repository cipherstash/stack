//go:build !unix

package guesttest

import "errors"

// SetMemlockLimit has nothing to lower where there is no RLIMIT_MEMLOCK.
func SetMemlockLimit(uint64) error { return errors.New("no RLIMIT_MEMLOCK on this platform") }
