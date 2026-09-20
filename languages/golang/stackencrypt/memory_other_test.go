//go:build !unix

package stackencrypt

import "errors"

func dropMemlockLimit() error { return errors.New("no RLIMIT_MEMLOCK on this platform") }
