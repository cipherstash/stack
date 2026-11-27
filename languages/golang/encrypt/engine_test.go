package encrypt

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

// fakeTimer is a timer the test fires itself.
type fakeTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func (t *fakeTimer) Stop() bool {
	was := !t.stopped
	t.stopped = true
	return was
}

// fakeEngines is an engineCache whose compiles are counted, whose frees
// are counted, and whose idle timers are recorded for the test to fire.
type fakeEngines struct {
	cache    *engineCache
	compiles atomic.Int32
	frees    atomic.Int32
	fail     atomic.Bool
	mu       sync.Mutex
	timers   []*fakeTimer
}

const fakeIdle = 7 * time.Minute

func newFakeEngines() *fakeEngines {
	f := &fakeEngines{}
	f.cache = &engineCache{
		idle: fakeIdle,
		afterFunc: func(d time.Duration, fn func()) stopper {
			f.mu.Lock()
			defer f.mu.Unlock()
			t := &fakeTimer{d: d, f: fn}
			f.timers = append(f.timers, t)
			return t
		},
		compile: func(context.Context, []byte) (func(), error) {
			f.compiles.Add(1)
			// Long enough for concurrent callers to overlap.
			time.Sleep(10 * time.Millisecond)
			if f.fail.Load() {
				return nil, errCompile
			}
			return func() { f.frees.Add(1) }, nil
		},
	}
	return f
}

// lastTimer is the timer started last, which must exist.
func (f *fakeEngines) lastTimer(t *testing.T) *fakeTimer {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.timers) == 0 {
		t.Fatal("no idle timer was started")
	}
	return f.timers[len(f.timers)-1]
}

func (f *fakeEngines) timerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.timers)
}

func (f *fakeEngines) want(t *testing.T, compiles, frees int32) {
	t.Helper()
	if got := f.compiles.Load(); got != compiles {
		t.Errorf("compiled %d times, want %d", got, compiles)
	}
	if got := f.frees.Load(); got != frees {
		t.Errorf("freed %d times, want %d", got, frees)
	}
}

// The compiled engine is shared by every open instance, kept while one is
// open, freed by the idle timer once the last has closed, and compiled
// again by the next instance after that.
func TestEngineCacheFreesTheEngineWhenIdle(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	a := f.cache.acquire(ctx, []byte("a"))
	b := f.cache.acquire(ctx, []byte("a"))
	f.want(t, 1, 0)

	a.release()
	if n := f.timerCount(); n != 0 {
		t.Fatalf("%d idle timers started with an instance still open, want 0", n)
	}
	b.release()
	timer := f.lastTimer(t)
	if timer.d != fakeIdle {
		t.Fatalf("idle timer of %v, want the cache's %v", timer.d, fakeIdle)
	}
	f.want(t, 1, 0)

	timer.f()
	f.want(t, 1, 1)

	c := f.cache.acquire(ctx, []byte("a"))
	f.want(t, 2, 1)
	c.release()
}

// An instance opened while the idle timer runs stops it and uses the
// compiled engine. The timer firing late, after Stop lost the race, frees
// nothing.
func TestEngineCacheReuseStopsTheIdleTimer(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	f.cache.acquire(ctx, []byte("a")).release()
	first := f.lastTimer(t)

	again := f.cache.acquire(ctx, []byte("a"))
	if !first.stopped {
		t.Fatal("the idle timer was not stopped when an instance opened")
	}
	first.f()
	f.want(t, 1, 0)

	again.release()
	second := f.lastTimer(t)
	first.f()
	f.want(t, 1, 0)
	second.f()
	f.want(t, 1, 1)
}

// ReleaseEngine frees the engine at once, stops its idle timer, and is
// safe to call again.
func TestEngineCacheReleaseAllFreesAtOnce(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	f.cache.acquire(ctx, []byte("a")).release()
	f.cache.acquire(ctx, []byte("b")).release()
	f.want(t, 2, 0)

	f.cache.releaseAll()
	f.want(t, 2, 2)
	for i, timer := range f.timers {
		if !timer.stopped {
			t.Errorf("idle timer %d is still running", i)
		}
		// A timer that fired anyway frees nothing a second time.
		timer.f()
	}
	f.cache.releaseAll()
	f.want(t, 2, 2)

	f.cache.acquire(ctx, []byte("a")).release()
	f.want(t, 3, 2)
}

// ReleaseEngine with an instance open drops the cache's own hold at once,
// and leaves the instance's alone: wazero keeps the compiled code for the
// instance's runtime until it closes. The instance's later release starts
// no timer, and a new instance compiles again.
func TestEngineCacheReleaseAllWithAnInstanceOpen(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	open := f.cache.acquire(ctx, []byte("a"))
	f.cache.releaseAll()
	f.want(t, 1, 1)

	next := f.cache.acquire(ctx, []byte("a"))
	f.want(t, 2, 1)

	open.release()
	if n := f.timerCount(); n != 0 {
		t.Fatalf("%d idle timers started for a build already released, want 0", n)
	}
	next.release()
	f.lastTimer(t).f()
	f.want(t, 2, 2)
}

// A release counts once, however often it runs, and a nil lease, from a
// compile that failed, releases nothing.
func TestEngineLeaseReleaseIsIdempotent(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	a := f.cache.acquire(ctx, []byte("a"))
	b := f.cache.acquire(ctx, []byte("a"))
	a.release()
	a.release()
	if n := f.timerCount(); n != 0 {
		t.Fatalf("a second release of one lease started %d idle timers, want 0", n)
	}
	b.release()
	f.lastTimer(t).f()
	f.want(t, 1, 1)

	var none *engineLease
	none.release()
}

// A compile that fails is not kept: the lease is nil, and the next
// instance tries again.
func TestEngineCacheDoesNotKeepAFailedCompile(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	f.fail.Store(true)
	if l := f.cache.acquire(ctx, []byte("a")); l != nil {
		t.Fatal("a failed compile gave a lease")
	}
	f.fail.Store(false)
	l := f.cache.acquire(ctx, []byte("a"))
	if l == nil {
		t.Fatal("no lease after a compile that worked")
	}
	f.want(t, 2, 0)
	l.release()
}

// Instances that open at once over a build that is not compiled wait for
// one compile.
func TestEngineCacheCompilesOnceForConcurrentInstances(t *testing.T) {
	f := newFakeEngines()
	ctx := context.Background()
	leases := make([]*engineLease, 8)
	var wg sync.WaitGroup
	for i := range leases {
		wg.Go(func() { leases[i] = f.cache.acquire(ctx, []byte("a")) })
	}
	wg.Wait()
	f.want(t, 1, 0)
	for _, l := range leases {
		wg.Go(l.release)
	}
	wg.Wait()
	f.lastTimer(t).f()
	f.want(t, 1, 1)
}

// The real timer frees the engine once the idle period has passed, and the
// goroutine that runs it ends.
func TestEngineCacheRealTimerFreesTheEngine(t *testing.T) {
	freed := make(chan struct{})
	c := &engineCache{
		idle: time.Millisecond,
		compile: func(context.Context, []byte) (func(), error) {
			return func() { close(freed) }, nil
		},
	}
	c.acquire(context.Background(), []byte("a")).release()
	select {
	case <-freed:
	case <-time.After(10 * time.Second):
		t.Fatal("the idle timer did not free the engine")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.builds) != 0 {
		t.Fatalf("%d builds kept after the idle timer fired, want 0", len(c.builds))
	}
}

// The package's engines, over the real guest: checkers share one compile,
// ReleaseEngine called while one is open leaves it working, and a checker
// made once every earlier one has closed compiles again.
func TestReleaseEngineOverTheGuest(t *testing.T) {
	wasm := guestOrSkip(t)
	saved := engines
	t.Cleanup(func() { engines = saved })
	var compiles atomic.Int32
	engines = &engineCache{
		idle: time.Hour,
		compile: func(ctx context.Context, wasm []byte) (func(), error) {
			compiles.Add(1)
			return compileShared(ctx, wasm)
		},
	}
	ctx := context.Background()
	checker := func() *Checker {
		t.Helper()
		k, err := newCheckerOver(ctx, wasm)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	first := checker()
	second := checker()
	if got := compiles.Load(); got != 1 {
		t.Fatalf("two checkers compiled %d times, want 1", got)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	ReleaseEngine()
	ReleaseEngine()
	if _, err := first.Contexts(ctx, usersPlan()); err != nil {
		t.Fatalf("a checker open across ReleaseEngine: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	third := checker()
	defer func() { _ = third.Close() }()
	if got := compiles.Load(); got != 2 {
		t.Fatalf("compiled %d times, want 2: the checker after ReleaseEngine compiles again", got)
	}
	if _, err := third.Contexts(ctx, usersPlan()); err != nil {
		t.Fatal(err)
	}
}

// A compile that fails in the engine cache leaves the instance to fail on
// its own, with the error it always gave.
func TestNewInstanceReportsABadModuleItself(t *testing.T) {
	saved := engines
	t.Cleanup(func() { engines = saved })
	engines = &engineCache{idle: time.Hour}
	tr := &transport{rt: refusingTransport{}, token: noToken{}}
	if _, err := newInstance(context.Background(), []byte("not wasm"), tr, guest.BestEffort); err == nil {
		t.Fatal("instantiated bytes that are not a WebAssembly module")
	}
	engines.mu.Lock()
	defer engines.mu.Unlock()
	if len(engines.builds) != 0 {
		t.Fatal("kept a build that did not compile")
	}
}
