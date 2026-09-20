package stackencrypt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/sys"
)

// growProbe is a hand-assembled module with one page of memory and one
// export that grows it, so the allocator can be exercised without the
// guest:
//
//	(module
//	  (memory (export "memory") 1)
//	  (func (export "grow") (param i32) (result i32)
//	    local.get 0 memory.grow))
//
// Like the guest, it declares no maximum, so wazero asks the allocator for
// wasm's 4 GiB default.
var growProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
	0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // type: (i32) -> i32
	0x03, 0x02, 0x01, 0x00, // function: one, of type 0
	0x05, 0x03, 0x01, 0x00, 0x01, // memory: one, min 1 page, no max
	0x07, 0x11, 0x02, // exports: two
	0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00, // "memory" = memory 0
	0x04, 'g', 'r', 'o', 'w', 0x00, 0x00, // "grow" = func 0
	0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0x40, 0x00, 0x0b, // code
}

const wasmPage = 64 * 1024

// probeMemory instantiates growProbe under alloc and returns the base
// address of its memory and a grow function reporting the old page count.
func probeMemory(t *testing.T, alloc *memoryAllocator) (base func() uintptr, grow func(pages uint32) (old uint32, ok bool), done func()) {
	t.Helper()
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	mod, err := rt.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, alloc), growProbe, wazero.NewModuleConfig())
	if err != nil {
		_ = rt.Close(ctx)
		t.Fatalf("instantiating grow probe: %v", err)
	}
	base = func() uintptr {
		// Read returns a view into the buffer, not a copy.
		view, ok := mod.Memory().Read(0, 1)
		if !ok {
			t.Fatal("reading probe memory")
		}
		return uintptr(unsafe.Pointer(unsafe.SliceData(view)))
	}
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

// The whole point of owning the allocation: growth commits more of one
// reservation, so the buffer's address is the same before and after, and
// the guest's keys are never copied to a new slice.
func TestGuestMemoryDoesNotMoveOnGrowth(t *testing.T) {
	alloc := newMemoryAllocator(bestEffort)
	base, grow, done := probeMemory(t, alloc)
	defer done()
	if alloc.isFallback() {
		t.Skipf("heap fallback in use on this host: %v", alloc.lockError())
	}
	t.Logf("lock state on this host: %v", alloc.lockError())
	before := base()
	for _, pages := range []uint32{1, 15, 64} {
		if _, ok := grow(pages); !ok {
			t.Fatalf("grow(%d) refused", pages)
		}
		if after := base(); after != before {
			t.Fatalf("memory moved on grow(%d): %#x -> %#x", pages, before, after)
		}
	}
}

// The same property on the real guest: a host-staged buffer larger than
// the guest's initial memory makes it grow, and its memory stays where it
// was. On Linux with the lock granted the guest's own mapping is then
// checked in smaps, as the probe's is below.
func TestGuestGrowsInPlace(t *testing.T) {
	c := rawInstance(t)
	ctx := context.Background()
	mem := c.inst.module.Memory()
	base := func() uintptr {
		view, ok := mem.Read(0, 1)
		if !ok {
			t.Fatal("reading guest memory")
		}
		return uintptr(unsafe.Pointer(unsafe.SliceData(view)))
	}
	if c.inst.mem.isFallback() {
		t.Skipf("heap fallback in use on this host: %v", c.inst.mem.lockError())
	}
	before, pagesBefore := base(), mem.Size()/wasmPage
	staged, err := c.inst.allocWrite(ctx, make([]byte, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer c.inst.free(ctx, staged)
	if after := base(); after != before {
		t.Fatalf("guest memory moved on growth: %#x -> %#x", before, after)
	}
	if pagesAfter := mem.Size() / wasmPage; pagesAfter <= pagesBefore {
		t.Fatalf("guest memory did not grow: %d pages before, %d after", pagesBefore, pagesAfter)
	}
	if runtime.GOOS != "linux" {
		return
	}
	lockOrSkip(t, c.inst.mem)
	mapping, err := smapsEntry(base())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(" "+mapping.vmFlags+" ", " dd ") || !strings.Contains(" "+mapping.vmFlags+" ", " lo ") {
		t.Errorf("guest mapping VmFlags = %q, want dd and lo", mapping.vmFlags)
	}
	if mapping.lockedKB == 0 || mapping.lockedKB != mapping.rssKB {
		t.Errorf("guest mapping Locked = %d kB, Rss = %d kB", mapping.lockedKB, mapping.rssKB)
	}
}

// Free wipes then unmaps: the allocator reports the release, and the
// runtime close is what triggers it.
func TestGuestMemoryIsFreedOnRuntimeClose(t *testing.T) {
	alloc := newMemoryAllocator(bestEffort)
	_, grow, done := probeMemory(t, alloc)
	if _, ok := grow(3); !ok {
		t.Fatal("grow refused")
	}
	if alloc.isFreed() {
		t.Fatal("freed before close")
	}
	done()
	if !alloc.isFreed() {
		t.Fatal("runtime close did not free the guest memory")
	}
}

// The heap fallback keeps the two properties it can: growth wipes the
// slice it abandons, and Free wipes.
func TestHeapMemoryWipesWhatItAbandons(t *testing.T) {
	m := newHeapMemory(wasmPage, 4*wasmPage)
	first, _ := m.commit(wasmPage)
	first[0], first[wasmPage-1] = 0xAA, 0xBB
	second, _ := m.commit(3 * wasmPage)
	if second[0] != 0xAA || second[wasmPage-1] != 0xBB {
		t.Fatal("growth lost the contents")
	}
	if first[0] != 0 || first[wasmPage-1] != 0 {
		t.Fatal("growth left the abandoned slice unwiped")
	}
	if buf, _ := m.commit(5 * wasmPage); buf != nil {
		t.Fatal("grew past max")
	}
	// A size no slice on this host can hold is a refused growth, not a
	// panic. Only a 32-bit host can ask without the request being a real
	// allocation, so that is where it runs (CI's GOARCH=386 pass).
	if uint64(math.MaxInt) < 1<<40 {
		huge := newHeapMemory(0, 1<<40)
		if buf, _ := huge.commit(1 << 40); buf != nil {
			t.Fatal("a growth past the addressable size was granted")
		}
	}
	second[7] = 0xCC
	m.free()
	if second[7] != 0 {
		t.Fatal("free left the slice unwiped")
	}
}

// requireLock is set in CI, where RLIMIT_MEMLOCK has been raised, so the
// lock cannot quietly go untested. Without it a refused lock is reported
// and the assertion skipped: a developer laptop's default limit is not a
// bug in this package.
const requireLock = "STACKENCRYPT_TESTS_REQUIRE_LOCK"

func lockOrSkip(t *testing.T, alloc *memoryAllocator) {
	t.Helper()
	err := alloc.lockError()
	if err == nil {
		return
	}
	if alloc.isFallback() {
		// Not a refused lock: there was no reservation to lock (a 32-bit
		// host), which CI exercises on purpose under GOARCH=386.
		t.Skipf("heap fallback in use on this host: %v", err)
	}
	if os.Getenv(requireLock) != "" {
		t.Fatalf("%s is set and the lock was refused: %v", requireLock, err)
	}
	t.Skipf("lock refused on this host: %v", err)
}

// The lock is observable from the kernel's side: the mapping backing the
// probe shows as locked and, on Linux, non-dumpable, in /proc/self/smaps.
func TestGuestMemoryIsLockedAndNotDumpable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("smaps is Linux")
	}
	alloc := newMemoryAllocator(bestEffort)
	base, grow, done := probeMemory(t, alloc)
	defer done()
	// Grow past the initial commit so the flags are checked on a range
	// committed by Reallocate, after the mprotect split, not only on what
	// Allocate set up.
	if _, ok := grow(2); !ok {
		t.Fatal("grow refused")
	}
	lockOrSkip(t, alloc)
	mapping, err := smapsEntry(base())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(" "+mapping.vmFlags+" ", " dd ") {
		t.Errorf("VmFlags = %q, want dd (MADV_DONTDUMP)", mapping.vmFlags)
	}
	if !strings.Contains(" "+mapping.vmFlags+" ", " lo ") {
		t.Errorf("VmFlags = %q, want lo (mlock)", mapping.vmFlags)
	}
	if mapping.lockedKB == 0 || mapping.lockedKB != mapping.rssKB {
		t.Errorf("Locked = %d kB, Rss = %d kB: the committed range is not fully locked", mapping.lockedKB, mapping.rssKB)
	}
}

type smapsMapping struct {
	rssKB, lockedKB uint64
	vmFlags         string
}

// smapsEntry finds the /proc/self/smaps mapping containing addr.
func smapsEntry(addr uintptr) (smapsMapping, error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return smapsMapping{}, err
	}
	defer f.Close()
	var cur smapsMapping
	inside := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if lo, hi, ok := smapsRange(line); ok {
			if inside {
				return cur, nil
			}
			inside = addr >= lo && addr < hi
			cur = smapsMapping{}
			continue
		}
		if !inside {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch key {
		case "Rss":
			cur.rssKB = smapsKB(value)
		case "Locked":
			cur.lockedKB = smapsKB(value)
		case "VmFlags":
			cur.vmFlags = value
		}
	}
	if inside {
		return cur, nil
	}
	return smapsMapping{}, fmt.Errorf("no smaps mapping contains %#x", addr)
}

func smapsRange(line string) (lo, hi uintptr, ok bool) {
	head, _, _ := strings.Cut(line, " ")
	a, b, found := strings.Cut(head, "-")
	if !found {
		return 0, 0, false
	}
	l, err1 := strconv.ParseUint(a, 16, 64)
	h, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uintptr(l), uintptr(h), true
}

func smapsKB(value string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSuffix(value, " kB"), 10, 64)
	return n
}

// Strict mode is a NewClient failure, not a report. The refusal is
// provoked by lowering RLIMIT_MEMLOCK to zero, which is process-wide and
// irreversible for a non-root process, so it runs in a child.
func TestRequireLockedMemoryRefusesAnUnlockableGuest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no RLIMIT_MEMLOCK on Windows")
	}
	const child = "STACKENCRYPT_TEST_CHILD"
	if os.Getenv(child) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		out, err := cmd.CombinedOutput()
		switch {
		case strings.Contains(string(out), "case skipped:"):
			if os.Getenv(requireLock) != "" {
				t.Fatalf("%s is set and the refusal could not be provoked:\n%s", requireLock, out)
			}
			t.Skipf("refusal could not be provoked on this host:\n%s", out)
		case err != nil || !strings.Contains(string(out), "case ok"):
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	if err := dropMemlockLimit(); err != nil {
		t.Fatalf("lowering RLIMIT_MEMLOCK: %v", err)
	}
	// Can the lock be refused at all here? Root and CAP_IPC_LOCK ignore
	// the limit. On a 32-bit host there is no reservation to lock, and the
	// strict refusal is the reservation's, not the limit's.
	probe := newMemoryAllocator(bestEffort)
	_, _, done := probeMemory(t, probe)
	done()
	if probe.lockError() == nil {
		fmt.Println("case skipped: mlock succeeds under RLIMIT_MEMLOCK=0")
		return
	}
	limited := !probe.isFallback()
	cfg := Config{
		ClientID:            "6a70bd18-99ac-4650-b104-37eec3a15b09",
		ClientKey:           "00",
		Token:               StaticToken("t"),
		Guest:               wasiProbe,
		RequireLockedMemory: true,
	}
	_, err := NewClient(context.Background(), cfg)
	if !errors.Is(err, ErrMemoryLock) {
		t.Fatalf("strict NewClient under a refused lock: %v, want ErrMemoryLock", err)
	}
	if limited && !strings.Contains(err.Error(), "RLIMIT_MEMLOCK") {
		t.Fatalf("the error does not name the limit: %v", err)
	}
	// Best effort under the same refusal: the client exists, says so, and
	// shows it wherever it is printed or logged.
	if wasm, gerr := embeddedGuest(); gerr == nil {
		inst, err := newInstance(context.Background(), wasm, &transport{rt: http.DefaultTransport, token: cfg.Token}, bestEffort)
		if err != nil {
			t.Fatal(err)
		}
		c := newClient(inst, nil)
		defer c.Close()
		if c.MemoryLocked() {
			t.Fatal("best-effort client reports locked memory under a refused lock")
		}
		if err := c.MemoryLockError(); !errors.Is(err, ErrMemoryLock) {
			t.Fatalf("MemoryLockError = %v, want ErrMemoryLock", err)
		}
		if s := fmt.Sprint(c); !strings.Contains(s, "unlocked") || (limited && !strings.Contains(s, "RLIMIT_MEMLOCK")) {
			t.Fatalf("Client prints as %q: no memory state", s)
		}
		if v := c.LogValue().String(); !strings.Contains(v, "memory_locked=false") {
			t.Fatalf("Client logs as %q: no memory state", v)
		}
	}
	fmt.Println("case ok")
}

// reentrantProbe is a hand-assembled module reproducing the shape of the
// guest's transport import: "run" calls the host function h, then stores
// to memory. h re-enters the guest (as transport_send does through
// se_alloc) with a context that has ended, which is how wazero comes to
// free the module's memory while the guest is suspended in the import:
//
//	(module
//	  (import "env" "h" (func $h))
//	  (memory (export "memory") 1)
//	  (func (export "run") call $h i32.const 0 i32.const 1 i32.store)
//	  (func (export "nop")))
var reentrantProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
	0x02, 0x09, 0x01, 0x03, 'e', 'n', 'v', 0x01, 'h', 0x00, 0x00, // import env.h
	0x03, 0x03, 0x02, 0x00, 0x00, // two functions of type 0
	0x05, 0x03, 0x01, 0x00, 0x01, // memory: min 1, no max
	0x07, 0x16, 0x03,
	0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
	0x03, 'r', 'u', 'n', 0x00, 0x01,
	0x03, 'n', 'o', 'p', 0x00, 0x02,
	0x0a, 0x10, 0x02,
	0x0b, 0x00, 0x10, 0x00, 0x41, 0x00, 0x41, 0x01, 0x36, 0x02, 0x00, 0x0b, // run
	0x02, 0x00, 0x0b, // nop
}

// The sequence that crashed in CI: a call's context ends during a host
// import, the import re-enters the guest, and wazero frees the memory in
// that nested call while the outer guest frame is still live and about to
// store. The memory must survive until the outer call has returned; an
// unmapped store here is a fault in compiled code that takes the process
// down, so this test cannot fail gently.
func TestMemoryOutlivesACallClosedDuringAHostImport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alloc := newMemoryAllocator(bestEffort)
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer rt.Close(context.Background())
	var freedDuringImport, nestedFailed bool
	_, err := rt.NewHostModuleBuilder("env").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module) {
			cancel()
			_, nested := m.ExportedFunction("nop").Call(ctx)
			nestedFailed = nested != nil
			freedDuringImport = alloc.isFreed()
		}).Export("h").Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := rt.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, alloc), reentrantProbe, wazero.NewModuleConfig())
	if err != nil {
		t.Fatalf("instantiating reentrant probe: %v", err)
	}
	alloc.enter()
	_, err = mod.ExportedFunction("run").Call(ctx)
	alloc.exit()
	var exit *sys.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != sys.ExitCodeContextCanceled {
		t.Fatalf("run: %v, want the cancellation exit", err)
	}
	if !nestedFailed {
		t.Fatal("the nested call did not see the closed module")
	}
	if freedDuringImport {
		t.Fatal("memory freed while the guest was suspended in a host import")
	}
	if !alloc.isFreed() {
		t.Fatal("memory not freed once the outer call returned")
	}
}

// A Client that becomes unreachable without Close is released by its
// cleanup: the guest's shutdown runs and the memory is wiped and freed. It
// covers the forgot-to-close case in a running process, and nothing at
// exit.
func TestUnreachableClientIsReleased(t *testing.T) {
	wasm := guestOrSkip(t)
	inst, err := newInstance(context.Background(), wasm, &transport{rt: http.DefaultTransport, token: StaticToken("t")}, bestEffort)
	if err != nil {
		t.Fatal(err)
	}
	alloc := inst.mem
	func() {
		c := newClient(inst, nil)
		if c.inst.mem.isFreed() {
			t.Fatal("freed on construction")
		}
	}()
	inst = nil
	deadline := time.Now().Add(10 * time.Second)
	for !alloc.isFreed() {
		if time.Now().After(deadline) {
			t.Fatal("an unreachable client's memory was not released")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

// Close stops the cleanup, so a closed client is released exactly once.
func TestCloseStopsTheCleanup(t *testing.T) {
	c := rawInstance(t)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !c.inst.mem.isFreed() {
		t.Fatal("Close did not free the guest memory")
	}
	// Stop on a cleanup Close already stopped is a no-op, so a second Stop
	// here proves nothing on its own; what is pinned is that the release
	// ran once, through Close, and the memory is gone.
	c.cleanup.Stop()
}
