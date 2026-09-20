//go:build unix

package stackencrypt

import "golang.org/x/sys/unix"

// setMemlockLimit lowers RLIMIT_MEMLOCK to n bytes for this process. Only
// a child test process calls it.
func setMemlockLimit(n uint64) error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: n, Max: n})
}
