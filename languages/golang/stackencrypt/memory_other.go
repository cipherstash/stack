//go:build !unix && !windows

package stackencrypt

// Platforms with neither mmap nor VirtualAlloc in this package's
// vocabulary get the heap fallback: growth and release still wipe, nothing
// is locked, and the Client says so.
func reserveMemory(capacity, max uint64, _ lockPolicy) (backend, error) {
	return newHeapMemory(capacity, max), errNoLockSupport
}
