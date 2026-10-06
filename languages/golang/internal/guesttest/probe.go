// Package guesttest holds what the tests of the guest packages share: a
// hand-assembled probe module that exercises the memory allocator without
// a guest, the lock-limit machinery those tests need, and the skip rules
// for hosts that cannot run them. Internal, and imported only by _test
// files, so nothing here is API.
package guesttest

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
)

// GrowProbe is a hand-assembled module with one page of memory and one
// export that grows it, so the allocator can be exercised without a guest:
//
//	(module
//	  (memory (export "memory") 1)
//	  (func (export "grow") (param i32) (result i32)
//	    local.get 0 memory.grow))
//
// Like the guests, it declares no maximum, so wazero asks the allocator for
// wasm's 4 GiB default.
var GrowProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
	0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // type: (i32) -> i32
	0x03, 0x02, 0x01, 0x00, // function: one, of type 0
	0x05, 0x03, 0x01, 0x00, 0x01, // memory: one, min 1 page, no max
	0x07, 0x11, 0x02, // exports: two
	0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00, // "memory" = memory 0
	0x04, 'g', 'r', 'o', 'w', 0x00, 0x00, // "grow" = func 0
	0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0x40, 0x00, 0x0b, // code
}

// WasmPage is the size of one wasm memory page.
const WasmPage = 64 * 1024

// ProbeMemory instantiates GrowProbe under alloc and returns the base
// address of its memory and a grow function reporting the old page count.
func ProbeMemory(t *testing.T, alloc *guest.Allocator) (base func() uintptr, grow func(pages uint32) (old uint32, ok bool), done func()) {
	t.Helper()
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	mod, err := rt.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, alloc), GrowProbe, wazero.NewModuleConfig())
	if err != nil {
		_ = rt.Close(ctx)
		t.Fatalf("instantiating grow probe: %v", err)
	}
	base = func() uintptr { return MemoryBase(t, mod.Memory()) }
	grow = func(pages uint32) (uint32, bool) {
		res, err := mod.ExportedFunction("grow").Call(ctx, uint64(pages))
		if err != nil {
			t.Fatalf("grow: %v", err)
		}
		return uint32(res[0]), int32(res[0]) != -1
	}
	done = func() { _ = rt.Close(ctx) }
	return base, grow, done
}

// MemoryBase is the host address of a module memory's first byte. Read
// returns a view into the buffer, not a copy.
func MemoryBase(t *testing.T, mem api.Memory) uintptr {
	t.Helper()
	view, ok := mem.Read(0, 1)
	if !ok {
		t.Fatal("reading guest memory")
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(view)))
}

// HostReserves reports whether this host can back a guest with a
// reservation at all. Where it cannot (a 32-bit host asked for wasm's
// 4 GiB default, which CI exercises on purpose under GOARCH=386) the heap
// fallback is in use, no lock is possible, and the tests of a lock granted
// or refused have nothing to test: they skip, whatever RequireLock says.
func HostReserves(t *testing.T) bool {
	t.Helper()
	probe := guest.NewAllocator(guest.BestEffort)
	_, _, done := ProbeMemory(t, probe)
	done()
	return !probe.IsFallback()
}

// RequireLock is set in CI, where RLIMIT_MEMLOCK has been raised, so the
// lock cannot quietly go untested. Without it a refused lock is reported
// and the assertion skipped: a developer laptop's default limit is not a
// bug in these packages.
const RequireLock = "STACK_ENCRYPT_TESTS_REQUIRE_LOCK"

// LockOrSkip continues if alloc's memory is locked, skips if the host
// refused the lock (or has no reservation to lock), and fails the skip
// when RequireLock says the host was meant to grant it.
func LockOrSkip(t *testing.T, alloc *guest.Allocator) {
	t.Helper()
	err := alloc.LockError()
	if err == nil {
		return
	}
	if alloc.IsFallback() {
		// Not a refused lock: there was no reservation to lock (a 32-bit
		// host), which CI exercises on purpose under GOARCH=386.
		t.Skipf("heap fallback in use on this host: %v", err)
	}
	SkipUnlessLockRequired(t, "the lock was refused", err)
}

// SkipUnlessLockRequired skips a test the host cannot run — what says why,
// detail is the refusal or the child's output — unless RequireLock says the
// host was meant to, in which case it fails.
func SkipUnlessLockRequired(t *testing.T, what string, detail any) {
	t.Helper()
	if os.Getenv(RequireLock) != "" {
		t.Fatalf("%s is set and %s:\n%v", RequireLock, what, detail)
	}
	t.Skipf("%s on this host:\n%v", what, detail)
}

// InChild re-runs the calling test in a child process, for tests that
// lower RLIMIT_MEMLOCK: the change is process-wide and irreversible for a
// non-root process. It returns true in the child, which prints "case ok"
// when done or "case skipped: <why>" when the host cannot provoke the
// condition; the parent judges that output and returns false.
func InChild(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no RLIMIT_MEMLOCK on Windows")
	}
	const child = "STACKENCRYPT_TEST_CHILD"
	if os.Getenv(child) != "" {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	switch {
	case strings.Contains(string(out), "case skipped:"):
		SkipUnlessLockRequired(t, "the refusal could not be provoked", string(out))
	case err != nil || !strings.Contains(string(out), "case ok"):
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	return false
}
