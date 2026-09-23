//go:build !unix && !windows

package guest

// Platforms with neither mmap nor VirtualAlloc in this package's
// vocabulary get the heap fallback: growth and release still wipe, nothing
// is locked, and the Client says so.
func reserveMemory(capacity, max uint64, _ LockPolicy) (backend, error) {
	return newHeapMemory(capacity, max), errNoLockSupport
}
