//go:build !unix && !windows

package guest

import "errors"

// errNoLockSupport is the heap fallback's reason on platforms where this
// package has no lock implementation.
var errNoLockSupport = errors.New("guest memory cannot be locked on this platform")

// Platforms with neither mmap nor VirtualAlloc in this package's
// vocabulary get the heap fallback: growth and release still wipe, nothing
// is locked, and the Client says so.
func reserveMemory(capacity, max uint64, _ LockPolicy) (backend, error) {
	return newHeapMemory(capacity, max), errNoLockSupport
}
