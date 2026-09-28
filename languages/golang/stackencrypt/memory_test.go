package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero/api"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guesttest"
)

// The allocator on its own is tested in internal/guest. These are the
// properties a Client over the real guest has because of it, and what the
// Client reports about its memory.

// stageLarge stages a buffer larger than the guest's initial memory, so
// the guest must grow, and frees it again.
func stageLarge(ctx context.Context, inst *instance) error {
	staged, err := inst.exports.AllocWrite(ctx, inst.module, make([]byte, 2<<20))
	if err != nil {
		return err
	}
	inst.exports.Free(ctx, staged)
	return nil
}

// invoke calls one export on already-staged arguments and decodes its
// packed result, for the tests that need to refuse growth between staging
// and the call.
func invoke(ctx context.Context, fn api.Function, params ...uint64) error {
	res, err := fn.Call(ctx, params...)
	if err != nil {
		return fmt.Errorf("%w: guest call: %w", guest.ErrTrap, err)
	}
	_, _, err = guest.PackedResult(res[0])
	return err
}

// A host-staged buffer larger than the guest's initial memory makes it
// grow, and its memory stays where it was: growth commits more of one
// reservation, so the guest's keys are never copied to a new slice. The
// guest's own mapping is checked in smaps on Linux, in
// memory_linux_test.go.
func TestGuestGrowsInPlace(t *testing.T) {
	c := rawInstance(t)
	mem := c.inst.module.Memory()
	if c.inst.mem.IsFallback() {
		t.Skipf("heap fallback in use on this host: %v", c.inst.mem.LockError())
	}
	before, pagesBefore := guesttest.MemoryBase(t, mem), mem.Size()/guesttest.WasmPage
	if err := stageLarge(context.Background(), c.inst); err != nil {
		t.Fatal(err)
	}
	if after := guesttest.MemoryBase(t, mem); after != before {
		t.Fatalf("guest memory moved on growth: %#x -> %#x", before, after)
	}
	if pagesAfter := mem.Size() / guesttest.WasmPage; pagesAfter <= pagesBefore {
		t.Fatalf("guest memory did not grow: %d pages before, %d after", pagesBefore, pagesAfter)
	}
}

// Strict mode is a NewClient failure, not a report. The refusal is
// provoked by lowering RLIMIT_MEMLOCK to zero.
func TestRequireLockedMemoryRefusesAnUnlockableGuest(t *testing.T) {
	if !guesttest.InChild(t) {
		return
	}
	if err := guesttest.SetMemlockLimit(0); err != nil {
		t.Fatalf("lowering RLIMIT_MEMLOCK: %v", err)
	}
	// Can the lock be refused at all here? Root and CAP_IPC_LOCK ignore
	// the limit. On a 32-bit host there is no reservation to lock, and the
	// strict refusal is the reservation's, not the limit's.
	probe := guest.NewAllocator(guest.BestEffort)
	_, _, done := guesttest.ProbeMemory(t, probe)
	done()
	if probe.LockError() == nil {
		fmt.Println("case skipped: mlock succeeds under RLIMIT_MEMLOCK=0")
		return
	}
	limited := !probe.IsFallback()
	_, err := NewClient(context.Background(),
		WithCredentials(NewCredentials("6a70bd18-99ac-4650-b104-37eec3a15b09", NewClientKey([]byte("00")), StaticToken("t"))),
		WithGuest(wasiProbe),
		WithRequireLockedMemory(),
	)
	if !errors.Is(err, ErrMemoryLock) {
		t.Fatalf("strict NewClient under a refused lock: %v, want ErrMemoryLock", err)
	}
	if limited && !strings.Contains(err.Error(), "RLIMIT_MEMLOCK") {
		t.Fatalf("the error does not name the limit: %v", err)
	}
	// Best effort under the same refusal: the client exists, says so, and
	// shows it wherever it is printed or logged.
	if wasm, gerr := embeddedGuest(); gerr == nil {
		inst, err := newInstance(context.Background(), wasm, &transport{rt: http.DefaultTransport, token: StaticToken("t")}, guest.BestEffort)
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

// strictClient is a Client over the real guest under the strict policy,
// or a skip where this host refuses the lock.
func strictClient(t *testing.T) *Client {
	t.Helper()
	if !guesttest.HostReserves(t) {
		t.Skip("heap fallback in use on this host: a strict client cannot exist")
	}
	inst, err := newInstance(context.Background(), guestOrSkip(t), &transport{rt: http.DefaultTransport, token: StaticToken("t")}, guest.Strict)
	if errors.Is(err, ErrMemoryLock) {
		guesttest.SkipUnlessLockRequired(t, "the lock was refused", err)
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

// Through the Client: the call that needed the growth for a host-staged
// buffer fails with ErrMemoryLock naming the refusal, the client is still
// open, and it still reports locked memory everywhere it is asked — the
// method, the error, the print and the log.
func TestRequireLockedMemoryFailsTheCallThatCannotGrow(t *testing.T) {
	ctx := context.Background()
	c := strictClient(t)
	refusing := guest.RefuseGrowth(c.inst.mem, errors.New("refused for the test"))
	stage := func(inst *instance) ([]byte, error) { return nil, stageLarge(ctx, inst) }
	_, err := c.call(ctx, stage)
	if !errors.Is(err, ErrMemoryLock) || !strings.Contains(err.Error(), "growth refused") || !strings.Contains(err.Error(), refusing.Reason().Error()) {
		t.Fatalf("call needing a refused growth: %v; want ErrMemoryLock naming the refusal", err)
	}
	if refusing.Refused() == 0 {
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
	refusing.Allow()
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
	cfg := initConfig{clientID: strings.Repeat("a", 2<<20), clientKey: NewClientKey([]byte("00"))}
	encoded, err := encodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var refusing *guest.Refusing
	_, err = c.call(ctx, func(inst *instance) ([]byte, error) {
		staged, err := inst.exports.AllocWrite(ctx, inst.module, encoded)
		if err != nil {
			return nil, err
		}
		defer inst.exports.Free(ctx, staged)
		refusing = guest.RefuseGrowth(inst.mem, errors.New("refused for the test"))
		return nil, invoke(ctx, inst.cipherInit, uint64(staged.Ptr), uint64(staged.Len))
	})
	if !errors.Is(err, ErrMemoryLock) || !strings.Contains(err.Error(), "growth refused") {
		t.Fatalf("init needing a refused internal growth: %v; want ErrMemoryLock naming the refusal", err)
	}
	if refusing.Refused() == 0 {
		t.Fatal("the guest did not grow; the test proves nothing")
	}
	if !c.inst.module.IsClosed() || !strings.Contains(err.Error(), "the client is closed") {
		t.Fatalf("the guest's abort did not close the client: %v", err)
	}
	if !c.inst.mem.IsFreed() {
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

// A Client that becomes unreachable without Close is released by its
// cleanup: the guest's shutdown runs and the memory is wiped and freed. It
// covers the forgot-to-close case in a running process, and nothing at
// exit.
func TestUnreachableClientIsReleased(t *testing.T) {
	wasm := guestOrSkip(t)
	inst, err := newInstance(context.Background(), wasm, &transport{rt: http.DefaultTransport, token: StaticToken("t")}, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	alloc := inst.mem
	func() {
		c := newClient(inst, nil)
		if c.inst.mem.IsFreed() {
			t.Fatal("freed on construction")
		}
	}()
	inst = nil
	deadline := time.Now().Add(10 * time.Second)
	for !alloc.IsFreed() {
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
	if !c.inst.mem.IsFreed() {
		t.Fatal("Close did not free the guest memory")
	}
	// Stop on a cleanup Close already stopped is a no-op, so a second Stop
	// here proves nothing on its own; what is pinned is that the release
	// ran once, through Close, and the memory is gone.
	c.cleanup.Stop()
}
