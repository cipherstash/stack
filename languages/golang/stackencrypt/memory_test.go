package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"runtime"
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
	base = func() uintptr { return memoryBase(t, mod.Memory()) }
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

// memoryBase is the host address of a module memory's first byte. Read
// returns a view into the buffer, not a copy.
func memoryBase(t *testing.T, mem api.Memory) uintptr {
	t.Helper()
	view, ok := mem.Read(0, 1)
	if !ok {
		t.Fatal("reading guest memory")
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(view)))
}

// hostReserves reports whether this host can back the guest with a
// reservation at all. Where it cannot (a 32-bit host asked for wasm's
// 4 GiB default, which CI exercises on purpose under GOARCH=386) the heap
// fallback is in use, no lock is possible, and the tests of a lock granted
// or refused have nothing to test: they skip, whatever requireLock says.
func hostReserves(t *testing.T) bool {
	t.Helper()
	probe := newMemoryAllocator(bestEffort)
	_, _, done := probeMemory(t, probe)
	done()
	return !probe.isFallback()
}

// stageLarge stages a buffer larger than the guest's initial memory, so
// the guest must grow, and frees it again.
func stageLarge(ctx context.Context, inst *instance) error {
	staged, err := inst.allocWrite(ctx, make([]byte, 2<<20))
	if err != nil {
		return err
	}
	inst.free(ctx, staged)
	return nil
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
// was. The guest's own mapping is checked in smaps on Linux, in
// memory_linux_test.go.
func TestGuestGrowsInPlace(t *testing.T) {
	c := rawInstance(t)
	mem := c.inst.module.Memory()
	if c.inst.mem.isFallback() {
		t.Skipf("heap fallback in use on this host: %v", c.inst.mem.lockError())
	}
	before, pagesBefore := memoryBase(t, mem), mem.Size()/wasmPage
	if err := stageLarge(context.Background(), c.inst); err != nil {
		t.Fatal(err)
	}
	if after := memoryBase(t, mem); after != before {
		t.Fatalf("guest memory moved on growth: %#x -> %#x", before, after)
	}
	if pagesAfter := mem.Size() / wasmPage; pagesAfter <= pagesBefore {
		t.Fatalf("guest memory did not grow: %d pages before, %d after", pagesBefore, pagesAfter)
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
	skipUnlessLockRequired(t, "the lock was refused", err)
}

// skipUnlessLockRequired skips a test the host cannot run — what says why,
// detail is the refusal or the child's output — unless requireLock says the
// host was meant to, in which case it fails.
func skipUnlessLockRequired(t *testing.T, what string, detail any) {
	t.Helper()
	if os.Getenv(requireLock) != "" {
		t.Fatalf("%s is set and %s:\n%v", requireLock, what, detail)
	}
	t.Skipf("%s on this host:\n%v", what, detail)
}

// inChild re-runs the calling test in a child process, for tests that
// lower RLIMIT_MEMLOCK: the change is process-wide and irreversible for a
// non-root process. It returns true in the child, which prints "case ok"
// when done or "case skipped: <why>" when the host cannot provoke the
// condition; the parent judges that output and returns false.
func inChild(t *testing.T) bool {
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
		skipUnlessLockRequired(t, "the refusal could not be provoked", string(out))
	case err != nil || !strings.Contains(string(out), "case ok"):
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	return false
}

// Strict mode is a NewClient failure, not a report. The refusal is
// provoked by lowering RLIMIT_MEMLOCK to zero.
func TestRequireLockedMemoryRefusesAnUnlockableGuest(t *testing.T) {
	if !inChild(t) {
		return
	}
	if err := setMemlockLimit(0); err != nil {
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
		t.Cleanup(func() { _ = c.Close() })
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

// The same refusal on a growth, from the kernel: with RLIMIT_MEMLOCK at
// two pages the probe's first page locks and a growth by two more cannot.
// Strict refuses the growth and gives the range back, so the page the
// probe holds is still locked and the allocator still says so; the
// refusal is reported on its own, naming the limit.
func TestRequireLockedMemoryRefusesAnUnlockableGrowth(t *testing.T) {
	if !hostReserves(t) {
		t.Skip("heap fallback in use on this host: no reservation to lock")
	}
	if !inChild(t) {
		return
	}
	const limit = 2 * wasmPage
	if err := setMemlockLimit(limit); err != nil {
		t.Fatalf("lowering RLIMIT_MEMLOCK: %v", err)
	}
	alloc := newMemoryAllocator(strict)
	_, grow, done := probeMemory(t, alloc)
	defer done()
	if err := alloc.lockError(); err != nil {
		fmt.Printf("case skipped: the first page did not lock under RLIMIT_MEMLOCK=%d: %v\n", limit, err)
		return
	}
	if _, ok := grow(2); ok {
		fmt.Println("case skipped: mlock succeeds past RLIMIT_MEMLOCK")
		return
	}
	if err := alloc.lockError(); err != nil {
		t.Fatalf("a refused growth changed the lock report: %v", err)
	}
	g := alloc.growthRefusal()
	if g.refused != 1 || g.reason == nil {
		t.Fatalf("growthRefusal = %+v; want one, with the refusal", g)
	}
	if !strings.Contains(g.reason.Error(), "RLIMIT_MEMLOCK") || !strings.Contains(g.reason.Error(), "needs at least") {
		t.Fatalf("the refusal does not name the limit and the size held: %v", g.reason)
	}
	fmt.Println("case ok")
}

// refusingBackend stands in front of a real backend and refuses, as
// strict does, any commit past a size: nil buffer, the reason as the lock
// error, nothing admitted. Lifted, it delegates again. It exercises the
// allocator's and the Client's bookkeeping of a refused growth without a
// lock limit, so it runs on every host.
type refusingBackend struct {
	backend
	past    uint64
	reason  error
	refuse  bool
	refused int
}

func (b *refusingBackend) commit(size uint64) ([]byte, error) {
	if b.refuse && size > b.past {
		b.refused++
		return nil, b.reason
	}
	return b.backend.commit(size)
}

// refuseGrowth puts a refusingBackend in front of alloc's backing, set to
// refuse any growth past what is committed now. Called on the guest's
// goroutine, between calls, as the backing is.
func refuseGrowth(alloc *memoryAllocator) *refusingBackend {
	refusing := &refusingBackend{backend: alloc.backing, past: alloc.backing.(sized).size(), reason: errors.New("refused for the test"), refuse: true}
	alloc.backing = refusing
	return refusing
}

// sized is what the tests need of a backing to know where it stands.
type sized interface{ size() uint64 }

func (m *mappedMemory) size() uint64 { return m.committed }
func (m *heapMemory) size() uint64   { return uint64(len(m.buf)) }

// A refused growth is the growth's failure, not the memory's: the
// allocator counts it and keeps its reason, and the lock report — nil,
// or whatever this host refused at the start — is exactly what it was.
// Once the growth is let through the report is still unchanged.
func TestRefusedGrowthLeavesTheLockReportAlone(t *testing.T) {
	alloc := newMemoryAllocator(strict)
	base, grow, done := probeMemory(t, alloc)
	defer done()
	before := alloc.lockError()
	refusing := refuseGrowth(alloc)
	at := base()
	if _, ok := grow(1); ok {
		t.Fatal("the refused growth was granted")
	}
	if after := alloc.lockError(); after != before {
		t.Fatalf("the refused growth changed the lock report: %v -> %v", before, after)
	}
	if g := alloc.growthRefusal(); g.refused != 1 || g.reason != refusing.reason {
		t.Fatalf("growthRefusal = %+v; want one, with the refusal", g)
	}
	refusing.refuse = false
	if _, ok := grow(1); !ok {
		t.Fatal("growth refused once the backend lets it through")
	}
	if after := alloc.lockError(); after != before {
		t.Fatalf("a later growth changed the lock report: %v -> %v", before, after)
	}
	if g := alloc.growthRefusal(); g.refused != 1 {
		t.Fatalf("growthRefusal = %+v after a granted growth, want one", g)
	}
	// The heap fallback may copy on growth, and says so; a reservation
	// never does.
	if !alloc.isFallback() && base() != at {
		t.Fatal("memory moved across the refused growth")
	}
}

// strictClient is a Client over the real guest under the strict policy,
// or a skip where this host refuses the lock.
func strictClient(t *testing.T) *Client {
	t.Helper()
	if !hostReserves(t) {
		t.Skip("heap fallback in use on this host: a strict client cannot exist")
	}
	inst, err := newInstance(context.Background(), guestOrSkip(t), &transport{rt: http.DefaultTransport, token: StaticToken("t")}, strict)
	if errors.Is(err, ErrMemoryLock) {
		skipUnlessLockRequired(t, "the lock was refused", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(inst, nil)
	t.Cleanup(func() { _ = c.Close() })
	if !c.MemoryLocked() {
		t.Fatalf("a strict client reports unlocked memory: %v", c.MemoryLockError())
	}
	return c
}

// The same, through the Client: the call that needed the growth for a
// host-staged buffer fails with ErrMemoryLock naming the refusal, the
// client is still open, and it still reports locked memory everywhere it
// is asked — the method, the error, the print and the log.
func TestRequireLockedMemoryFailsTheCallThatCannotGrow(t *testing.T) {
	ctx := context.Background()
	c := strictClient(t)
	refusing := refuseGrowth(c.inst.mem)
	stage := func(inst *instance) ([]byte, error) { return nil, stageLarge(ctx, inst) }
	_, err := c.call(ctx, stage)
	if !errors.Is(err, ErrMemoryLock) || !strings.Contains(err.Error(), "growth refused") || !strings.Contains(err.Error(), refusing.reason.Error()) {
		t.Fatalf("call needing a refused growth: %v; want ErrMemoryLock naming the refusal", err)
	}
	if refusing.refused == 0 {
		t.Fatal("the guest did not grow; the test proves nothing")
	}
	if !c.MemoryLocked() {
		t.Fatalf("a refused growth unlocked the report: %v", c.MemoryLockError())
	}
	if err := c.MemoryLockError(); err != nil {
		t.Fatalf("MemoryLockError = %v after a refused growth, want nil", err)
	}
	if s := fmt.Sprint(c); !strings.HasSuffix(s, "memory: locked}") {
		t.Fatalf("Client prints as %q after a refused growth", s)
	}
	if v := c.LogValue().String(); !strings.Contains(v, "memory_locked=true") {
		t.Fatalf("Client logs as %q after a refused growth", v)
	}
	// The client is still open, and grows once it can.
	refusing.refuse = false
	if _, err := c.call(ctx, stage); err != nil {
		t.Fatalf("the next call, growth allowed: %v", err)
	}
	if !c.MemoryLocked() {
		t.Fatalf("the report changed on a granted growth: %v", c.MemoryLockError())
	}
}

// A growth the guest needs for an allocation of its own is refused the
// same way, but the guest cannot report it: its allocator aborts, the trap
// closes the module, and the client is closed with it, its keys wiped.
// The call still fails with ErrMemoryLock naming the refusal, and the
// client is ErrState from then on. Provoked by staging a config the guest
// must copy while decoding, with the refusal installed after the staging.
func TestRequireLockedMemoryClosesTheClientOnARefusedInternalGrowth(t *testing.T) {
	ctx := context.Background()
	c := strictClient(t)
	cfg := Config{ClientID: strings.Repeat("a", 2<<20), ClientKey: "00", Token: StaticToken("t")}
	encoded, err := encodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var refusing *refusingBackend
	_, err = c.call(ctx, func(inst *instance) ([]byte, error) {
		staged, err := inst.allocWrite(ctx, encoded)
		if err != nil {
			return nil, err
		}
		defer inst.free(ctx, staged)
		refusing = refuseGrowth(inst.mem)
		_, err = inst.invoke(ctx, inst.cipherInit, uint64(staged.ptr), uint64(staged.len))
		return nil, err
	})
	if !errors.Is(err, ErrMemoryLock) || !strings.Contains(err.Error(), "growth refused") {
		t.Fatalf("init needing a refused internal growth: %v; want ErrMemoryLock naming the refusal", err)
	}
	if refusing.refused == 0 {
		t.Fatal("the guest did not grow; the test proves nothing")
	}
	if !c.inst.module.IsClosed() || !strings.Contains(err.Error(), "the client is closed") {
		t.Fatalf("the guest's abort did not close the client: %v", err)
	}
	if !c.inst.mem.isFreed() {
		t.Fatal("the closed client's memory was not wiped and freed")
	}
	if _, err := c.call(ctx, func(*instance) ([]byte, error) { return nil, nil }); !errors.Is(err, ErrState) {
		t.Fatalf("a call after the abort: %v, want ErrState", err)
	}
	if !c.MemoryLocked() {
		t.Fatalf("a refused growth unlocked the report: %v", c.MemoryLockError())
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close after the abort: %v", err)
	}
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
