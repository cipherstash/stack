//go:build unix

package stackencrypt

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

// mappedMemory is the Unix backend: one anonymous private mapping of the
// declared maximum, reserved PROT_NONE so it costs address space only, and
// committed (made readable and writable) from the front as the guest grows.
// The base never changes, so wazero's buffer never moves. Each newly
// committed range is locked; the whole reservation is excluded from dumps
// once, at reservation, on the platforms that can (memory_linux.go).
type mappedMemory struct {
	mapping   []byte // the whole reservation
	committed uint64 // bytes made accessible so far, from the front
	strict    bool
	err       error // first lock or dump-exclusion refusal; never cleared
}

// reserveMemory returns a mapped memory for the reservation, or a heap
// memory when the reservation itself is impossible: max exceeds what this
// process can address (a 32-bit host asked for wasm's 4 GiB default), or
// mmap refused it.
func reserveMemory(capacity, max uint64, strict bool) guestMemory {
	if max > math.MaxInt {
		return newHeapMemory(capacity, max, fmt.Errorf("cannot reserve %s of address space on this host", byteCount(max)))
	}
	mapping, err := unix.Mmap(-1, 0, int(max), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANON|reserveFlags)
	if err != nil {
		return newHeapMemory(capacity, max, fmt.Errorf("reserving %s of address space: %w", byteCount(max), err))
	}
	m := &mappedMemory{mapping: mapping, strict: strict}
	if err := excludeFromDumps(mapping); err != nil {
		m.err = err
	}
	return m
}

// Reallocate implements experimental.LinearMemory. Growth commits the
// next range of the reservation and locks it. A lock refusal is recorded
// and, in strict mode, undone: the range goes back to inaccessible and nil
// is returned, which the guest sees as a failed memory.grow. The first
// commit is the exception: wazero cannot instantiate on a nil buffer, so
// it is granted and the refusal recorded, and newInstance turns it into
// the ErrMemoryLock the strict caller asked for. Shrinking is not
// something wasm does; a smaller size just shortens the view.
func (m *mappedMemory) Reallocate(size uint64) []byte {
	if size > uint64(len(m.mapping)) {
		return nil
	}
	if size > m.committed {
		fresh := m.mapping[m.committed:size]
		if err := unix.Mprotect(fresh, unix.PROT_READ|unix.PROT_WRITE); err != nil {
			return nil
		}
		if err := lock(fresh); err != nil {
			if m.err == nil {
				m.err = err
			}
			if m.strict && m.committed > 0 {
				// Nothing was written to the range yet; giving it back
				// leaves the guest exactly where it was.
				_ = unix.Mprotect(fresh, unix.PROT_NONE)
				return nil
			}
		}
		m.committed = size
	}
	return m.mapping[:size:size]
}

// Free implements experimental.LinearMemory: wipe what was committed, then
// release the reservation. munmap drops any lock with the pages.
func (m *mappedMemory) Free() {
	if m.mapping == nil {
		return
	}
	wipeMapped(m.mapping[:m.committed])
	_ = unix.Munmap(m.mapping)
	m.mapping = nil
	m.committed = 0
}

func (m *mappedMemory) lockError() error { return m.err }

// lock pins a committed range in RAM. The refusal names the limit that
// caused it, so an operator reading the error knows what to raise.
func lock(b []byte) error {
	if err := unix.Mlock(b); err != nil {
		return fmt.Errorf("locking %s of guest memory: %w (%s)", byteCount(uint64(len(b))), err, memlockLimit())
	}
	return nil
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
