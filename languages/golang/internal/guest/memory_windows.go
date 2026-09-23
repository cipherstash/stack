package guest

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows primitives behind mappedMemory: the declared maximum is
// reserved once (MEM_RESERVE), committed with MEM_COMMIT, locked with
// VirtualLock, released with MEM_RELEASE. Windows has no per-mapping dump
// exclusion.

func reserveRange(max int) ([]byte, error) {
	base, err := windows.VirtualAlloc(0, uintptr(max), windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	if err != nil {
		return nil, err
	}
	// The reservation is not Go memory; going through unsafe.Add keeps
	// the conversion within what vet's unsafeptr check accepts.
	return unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(nil), base)), max), nil
}

func address(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

func commitRange(b []byte) error {
	_, err := windows.VirtualAlloc(address(b), uintptr(len(b)), windows.MEM_COMMIT, windows.PAGE_READWRITE)
	return err
}

func decommitRange(b []byte) {
	_ = windows.VirtualFree(address(b), uintptr(len(b)), windows.MEM_DECOMMIT)
}

// lockRange pins a committed range in RAM. VirtualLock is bounded by the
// process's minimum working set, which defaults to a few hundred KiB, so
// the refusal says what to raise.
func lockRange(b []byte) error {
	if err := windows.VirtualLock(address(b), uintptr(len(b))); err != nil {
		return fmt.Errorf("locking %s of guest memory: %w (bounded by the process minimum working set; raise it with SetProcessWorkingSetSize before NewClient)", byteCount(uint64(len(b))), err)
	}
	return nil
}

// releaseRange frees the whole reservation, dropping any lock with it.
func releaseRange(mapping []byte) {
	_ = windows.VirtualFree(address(mapping), 0, windows.MEM_RELEASE)
}

// excludeFromDumps has no Windows equivalent.
func excludeFromDumps([]byte) error { return nil }
