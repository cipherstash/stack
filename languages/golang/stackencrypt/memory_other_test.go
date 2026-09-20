//go:build !unix

package stackencrypt

import "errors"

func setMemlockLimit(uint64) error { return errors.New("no RLIMIT_MEMLOCK on this platform") }
