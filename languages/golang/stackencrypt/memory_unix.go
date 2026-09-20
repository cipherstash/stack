//go:build unix

package stackencrypt

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// The Unix primitives behind mappedMemory: an anonymous private mapping
// reserved PROT_NONE so it costs address space only, committed with
// mprotect, locked with mlock, released with munmap.

func reserveRange(max int) ([]byte, error) {
	return unix.Mmap(-1, 0, max, unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANON|reserveFlags)
}

func commitRange(b []byte) error {
	return unix.Mprotect(b, unix.PROT_READ|unix.PROT_WRITE)
}

func decommitRange(b []byte) {
	_ = unix.Mprotect(b, unix.PROT_NONE)
}

// lockRange pins a committed range in RAM. The refusal names the limit
// that caused it and how to raise it, so an operator reading the error
// has the fix in hand.
func lockRange(b []byte) error {
	if err := unix.Mlock(b); err != nil {
		return fmt.Errorf("locking %s of guest memory: %w (%s; raise it with ulimit -l, a systemd LimitMEMLOCK=, or a pod securityContext)", byteCount(uint64(len(b))), err, memlockLimit())
	}
	return nil
}

func releaseRange(mapping []byte) {
	_ = unix.Munmap(mapping)
}

// memlockLimit describes RLIMIT_MEMLOCK for a lock refusal.
func memlockLimit() string {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return "RLIMIT_MEMLOCK unknown"
	}
	if lim.Cur == unix.RLIM_INFINITY {
		return "RLIMIT_MEMLOCK is unlimited"
	}
	return fmt.Sprintf("RLIMIT_MEMLOCK is %s", byteCount(uint64(lim.Cur)))
}
