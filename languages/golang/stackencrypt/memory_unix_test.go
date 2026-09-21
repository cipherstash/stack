//go:build unix

package stackencrypt

import "golang.org/x/sys/unix"

// setMemlockLimit lowers RLIMIT_MEMLOCK to n bytes for this process. Only
// a child test process calls it.
func setMemlockLimit(n uint64) error {
	var lim unix.Rlimit
	setRlim(&lim.Cur, n)
	setRlim(&lim.Max, n)
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim)
}

// setRlim assigns a limit whatever width the platform gives the field
// (unsigned on Linux and Darwin, signed on the BSDs).
func setRlim[T ~int64 | ~uint64](field *T, n uint64) { *field = T(n) }
