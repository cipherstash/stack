//go:build unix

package stackencrypt

import "golang.org/x/sys/unix"

// dropMemlockLimit lowers RLIMIT_MEMLOCK to zero for this process. Only a
// child test process calls it.
func dropMemlockLimit() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: 0})
}
