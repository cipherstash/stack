//go:build unix || windows

package guest

import (
	"fmt"
	"math"
	"runtime"
)

// mappedMemory is the reservation-backed memory: one range of the declared
// maximum reserved up front, inaccessible until committed (made readable
// and writable) from the front as the guest grows. The base never changes,
// so wazero's buffer never moves. Each newly committed range is locked;
// the whole reservation is excluded from dumps once, at reservation, on
// the platforms that can. The platform supplies the five primitives
// (memory_unix.go, memory_windows.go); the shape is the same on both.
type mappedMemory struct {
	mapping   []byte // the whole reservation
	committed uint64 // bytes made accessible so far, from the front
	policy    LockPolicy
}

// reserveMemory returns a mapped memory for the reservation, or a heap
// memory when the reservation itself is impossible: max exceeds what this
// process can address (a 32-bit host asked for wasm's 4 GiB default), or
// the platform refused it. The error is the reason the memory is not, or
// not fully, protected; nil when it is.
func reserveMemory(capacity, max uint64, policy LockPolicy) (backend, error) {
	if max > math.MaxInt {
		return newHeapMemory(capacity, max), fmt.Errorf("cannot reserve %s of address space on this host", byteCount(max))
	}
	mapping, err := reserveRange(int(max))
	if err != nil {
		return newHeapMemory(capacity, max), fmt.Errorf("reserving %s of address space: %w", byteCount(max), err)
	}
	return &mappedMemory{mapping: mapping, policy: policy}, excludeFromDumps(mapping)
}

// commit implements backend. Shrinking is not something wasm does; a
// smaller size just shortens the view.
func (m *mappedMemory) commit(size uint64) ([]byte, error) {
	if size > uint64(len(m.mapping)) {
		return nil, nil
	}
	if size > m.committed {
		fresh := m.mapping[m.committed:size]
		if err := commitRange(fresh); err != nil {
			return nil, nil
		}
		if err := lockRange(fresh); err != nil {
			// The platform names the range it could not lock; the
			// operator sizing a limit needs the whole of what the guest
			// holds with it.
			err = fmt.Errorf("%w; the guest needs at least %s locked", err, byteCount(size))
			if m.policy == Strict && m.committed > 0 {
				// Nothing was written to the range yet; giving it back
				// leaves the guest exactly where it was.
				decommitRange(fresh)
				return nil, err
			}
			m.committed = size
			return m.mapping[:size:size], err
		}
		m.committed = size
	}
	return m.mapping[:size:size], nil
}

// free implements backend: wipe what was committed, then release the
// reservation, which drops any lock with the pages.
func (m *mappedMemory) free() {
	if m.mapping == nil {
		return
	}
	wipeMapped(m.mapping[:m.committed])
	releaseRange(m.mapping)
	m.mapping = nil
	m.committed = 0
}

// wipeMapped zeroes a committed range before its mapping is released. The
// stores go to memory that a syscall unmaps straight after, which the
// compiler cannot see through, so they are not dead stores it could drop;
// the volatile-store dance a C wipe needs has no Go equivalent and no need
// here. KeepAlive pins the slice past the stores so nothing reorders the
// wipe after the release.
func wipeMapped(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}
