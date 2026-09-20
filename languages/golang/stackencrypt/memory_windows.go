package stackencrypt

import (
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mappedMemory is the Windows backend, the same shape as the Unix one:
// the declared maximum is reserved once (MEM_RESERVE), committed from the
// front as the guest grows, and each committed range is locked with
// VirtualLock. Windows has no per-mapping dump exclusion.
type mappedMemory struct {
	base      uintptr
	mapping   []byte
	committed uint64
	strict    bool
	err       error
}

func reserveMemory(capacity, max uint64, strict bool) guestMemory {
	if max > math.MaxInt {
		return newHeapMemory(capacity, max, fmt.Errorf("cannot reserve %s of address space on this host", byteCount(max)))
	}
	base, err := windows.VirtualAlloc(0, uintptr(max), windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	if err != nil {
		return newHeapMemory(capacity, max, fmt.Errorf("reserving %s of address space: %w", byteCount(max), err))
	}
	// The reservation is not Go memory; going through unsafe.Add keeps
	// the conversion within what vet's unsafeptr check accepts.
	start := (*byte)(unsafe.Add(unsafe.Pointer(nil), base))
	return &mappedMemory{
		base:    base,
		mapping: unsafe.Slice(start, int(max)),
		strict:  strict,
	}
}

func (m *mappedMemory) Reallocate(size uint64) []byte {
	if size > uint64(len(m.mapping)) {
		return nil
	}
	if size > m.committed {
		fresh := m.mapping[m.committed:size]
		start := m.base + uintptr(m.committed)
		if _, err := windows.VirtualAlloc(start, uintptr(len(fresh)), windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
			return nil
		}
		if err := windows.VirtualLock(start, uintptr(len(fresh))); err != nil {
			if m.err == nil {
				// VirtualLock is bounded by the process's minimum working
				// set, which defaults to a few hundred KiB: raise it with
				// SetProcessWorkingSetSize before NewClient.
				m.err = fmt.Errorf("locking %s of guest memory: %w (bounded by the process minimum working set)", byteCount(uint64(len(fresh))), err)
			}
			if m.strict && m.committed > 0 { // see the Unix backend
				_ = windows.VirtualFree(start, uintptr(len(fresh)), windows.MEM_DECOMMIT)
				return nil
			}
		}
		m.committed = size
	}
	return m.mapping[:size:size]
}

func (m *mappedMemory) Free() {
	if m.mapping == nil {
		return
	}
	wipeMapped(m.mapping[:m.committed])
	// MEM_RELEASE frees the whole reservation and drops any lock with it.
	_ = windows.VirtualFree(m.base, 0, windows.MEM_RELEASE)
	m.mapping = nil
	m.committed = 0
}

func (m *mappedMemory) lockError() error { return m.err }
