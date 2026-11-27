package encrypt

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testclient"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

var errCompile = errors.New("compile failed")

// isPinned reports whether c keeps wasm pinned.
func isPinned(c *engineCache, wasm []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.builds[sha256.Sum256(wasm)]
	return ok && e.pinned
}

// A test build compiles once in a process, however many clients start and
// close, one after another or at once, and whatever ReleaseEngine does.
// wazero drops a compiled module from its in-memory cache when the last
// runtime using it closes, so without the pin every client in a suite that
// starts one per test compiled the guest again: about ten seconds each
// under the race detector.
func TestEngineCachePin(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name string
		run  func(t *testing.T, f *fakeEngines)
		want int32
	}{
		{
			name: "one build pinned twice compiles once",
			run: func(t *testing.T, f *fakeEngines) {
				f.cache.pin(ctx, []byte("a"))
				f.cache.pin(ctx, []byte("a"))
			},
			want: 1,
		},
		{
			name: "one build pinned at once by many callers compiles once",
			run: func(t *testing.T, f *fakeEngines) {
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { f.cache.pin(ctx, []byte("a")) })
				}
				wg.Wait()
			},
			want: 1,
		},
		{
			name: "each build compiles once",
			run: func(t *testing.T, f *fakeEngines) {
				f.cache.pin(ctx, []byte("a"))
				f.cache.pin(ctx, []byte("b"))
				f.cache.pin(ctx, []byte("a"))
			},
			want: 2,
		},
		{
			name: "a failed compile is not pinned",
			run: func(t *testing.T, f *fakeEngines) {
				f.fail.Store(true)
				f.cache.pin(ctx, []byte("a"))
				if isPinned(f.cache, []byte("a")) {
					t.Fatal("pinned a build that did not compile")
				}
				f.fail.Store(false)
				f.cache.pin(ctx, []byte("a"))
				f.cache.pin(ctx, []byte("a"))
			},
			want: 2,
		},
		{
			name: "a pinned build outlives its instances and releaseAll",
			run: func(t *testing.T, f *fakeEngines) {
				f.cache.pin(ctx, []byte("a"))
				f.cache.acquire(ctx, []byte("a")).release()
				if n := f.timerCount(); n != 0 {
					t.Fatalf("started %d idle timers on a pinned build, want 0", n)
				}
				f.cache.releaseAll()
				f.cache.releaseAll()
				f.cache.acquire(ctx, []byte("a")).release()
				if !isPinned(f.cache, []byte("a")) {
					t.Fatal("releaseAll dropped a pinned build")
				}
			},
			want: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeEngines()
			tt.run(t, f)
			f.want(t, tt.want, 0)
		})
	}
}

// A test client pins the build it runs, so that the next client over the
// same build reads the compiled code from the cache. Every test client is
// built by seededClient, package encrypttest's included. Each build is its
// own subtest, so a build that is absent shows as a skip.
func TestSeededClientPinsItsBuild(t *testing.T) {
	eqlBuild := func() ([]byte, error) {
		wasm, err := os.ReadFile(deterministicEQLGuestPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrDeterministicEQLGuestNotBuilt
		}
		return wasm, err
	}
	for _, build := range []struct {
		name   string
		load   func() ([]byte, error)
		absent error
	}{
		{"without the EQL types", DeterministicGuest, ErrDeterministicGuestNotBuilt},
		{"with the EQL types", eqlBuild, ErrDeterministicEQLGuestNotBuilt},
	} {
		t.Run(build.name, func(t *testing.T) {
			wasm, err := build.load()
			if errors.Is(err, build.absent) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			c, err := seededClient(context.Background(), wasm, [32]byte{7})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Error(err)
			}
			if !isPinned(engines, wasm) {
				t.Fatal("seededClient did not pin the build it ran")
			}
		})
	}
}

// The real compile, over the guest this package embeds: once a build is
// pinned, a runtime that compiles it reads the cache, even after every
// other runtime that used the build has closed, and after releaseAll.
// Without the pin, wazero drops the build from the cache when the first
// runtime closes, and the last compile below takes as long as a cold one.
func TestAPinnedBuildStaysCompiled(t *testing.T) {
	wasm, err := plainGuest()
	if errors.Is(err, ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := &engineCache{idle: time.Hour}
	t.Cleanup(func() { freeEverything(c) })
	c.pin(ctx, []byte("not wasm"))
	if isPinned(c, []byte("not wasm")) {
		t.Fatal("pinned bytes that are not a WebAssembly module")
	}
	// wazero compiles to machine code on amd64 and arm64 only. Elsewhere,
	// such as the 386 run in CI, it runs an interpreter, whose compile is
	// cheap. There a compile that reads the cache is only about 3 times
	// faster than one that misses it, which is too close to tell apart.
	if goruntime.GOARCH != "amd64" && goruntime.GOARCH != "arm64" {
		t.Skipf("wazero has no compiler on %s, so a cache hit cannot be told from a miss by time", goruntime.GOARCH)
	}
	// The compiles below run on one worker, so a compile that misses the
	// cache takes about 20 times as long as one that reads it, on any
	// number of cores. With a worker for each core, on 20 cores, it takes
	// only about 5 times as long.
	//
	// compile compiles wasm on a new runtime, closes the compiled module
	// and the runtime, and returns how long the compile took. Closing the
	// compiled module is what closing a client does: newInstance
	// instantiates from bytes, and wazero closes a module compiled that way
	// with the module.
	compile := func(config wazero.RuntimeConfig) time.Duration {
		t.Helper()
		runtime := wazero.NewRuntimeWithConfig(ctx, config)
		defer func() { _ = runtime.Close(ctx) }()
		start := time.Now()
		compiled, err := runtime.CompileModule(ctx, wasm)
		if err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		_ = compiled.Close(ctx)
		return elapsed
	}
	cold := compile(wazero.NewRuntimeConfig().WithCompilationCache(wazero.NewCompilationCache()))

	c.pin(ctx, wasm)
	c.releaseAll()
	shared := guestRuntimeConfig()
	compile(shared)
	if again := compile(shared); again > cold/4 {
		t.Fatalf("a compile after the pin took %v and a cold compile %v: the pinned build left the cache", again, cold)
	}
}

// encrypttest.AssertContexts and encrypttest.Contexts make a new checker
// on every call, and close it before they return. A checker over a test
// build compiles that build once in a process, however many are made and
// closed, and whatever ReleaseEngine does. Before, each call compiled the
// guest again: under the race detector, 10 to 50 seconds a call.
func TestTestCheckersCompileTheirBuildOnce(t *testing.T) {
	if _, err := plainGuest(); errors.Is(err, ErrGuestNotBuilt) {
		t.Skip(err)
	}
	var calls atomic.Int32
	swapEngines(t, &engineCache{
		idle: time.Hour,
		compile: func(ctx context.Context, wasm []byte) (func(), error) {
			calls.Add(1)
			return compileShared(ctx, wasm)
		},
	})
	ctx := context.Background()
	plan := &record.Plan{
		Context: []string{"users"},
		Fields:  []record.Field{{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext}}},
	}
	// The same loader for both builds: whichever one selectBuild picks in
	// this binary, it is this build.
	builds := testclient.Builds{Plain: plainGuest, WithEQL: plainGuest}
	for range 3 {
		checker, err := testChecker(ctx, builds)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checker.Contexts(ctx, plan); err != nil {
			t.Fatal(err)
		}
		if err := checker.Close(); err != nil {
			t.Fatal(err)
		}
		ReleaseEngine()
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("compiled %d times, want 1", got)
	}
}

// The checker package encrypttest gets, through internal/testclient, pins
// the test build that selectBuild picks, in engines, where test clients
// pin theirs. So encrypttest.Contexts compiles that build at most once in
// a test binary, and none at all after NewClient.
func TestTheRegisteredTestCheckerPinsItsBuild(t *testing.T) {
	eqlBuild := func() ([]byte, error) {
		wasm, err := os.ReadFile(deterministicEQLGuestPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrDeterministicEQLGuestNotBuilt
		}
		return wasm, err
	}
	wasm, err := selectBuild(DeterministicGuest, eqlBuild)
	if errors.Is(err, ErrDeterministicGuestNotBuilt) || errors.Is(err, ErrDeterministicEQLGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	built, err := testclient.NewChecker(context.Background(), testclient.Builds{Plain: DeterministicGuest, WithEQL: eqlBuild})
	if err != nil {
		t.Fatal(err)
	}
	checker, ok := built.(*Checker)
	if !ok {
		t.Fatalf("the checker constructor returned %T, not *Checker", built)
	}
	if err := checker.Close(); err != nil {
		t.Error(err)
	}
	if !isPinned(engines, wasm) {
		t.Fatal("the registered checker constructor did not pin the build it ran")
	}
}

// A test build that is not there is the loader's error, and nothing is
// compiled or kept.
func TestATestCheckerWithoutItsBuildIsTheLoadersError(t *testing.T) {
	f := newFakeEngines()
	swapEngines(t, f.cache)
	missing := func() ([]byte, error) { return nil, errCompile }
	if _, err := testChecker(context.Background(), testclient.Builds{Plain: missing, WithEQL: missing}); !errors.Is(err, errCompile) {
		t.Fatalf("%v, want the loader's error", err)
	}
	f.want(t, 0, 0)
}

// A test build that does not compile fails as a production build does:
// the instance reports it, so there is one error for a bad module, from
// test clients and checkers as from NewClient and NewChecker.
func TestABadTestBuildIsTheInstancesError(t *testing.T) {
	c := &engineCache{idle: time.Hour}
	swapEngines(t, c)
	bad := func() ([]byte, error) { return []byte("not wasm"), nil }
	builds := testclient.Builds{Plain: bad, WithEQL: bad}
	ctx := context.Background()
	if _, err := testChecker(ctx, builds); err == nil || !strings.HasPrefix(err.Error(), "encrypt: instantiating guest: ") {
		t.Errorf("testChecker over a bad build: %v, want the instance's error", err)
	}
	if _, err := seededClient(ctx, []byte("not wasm"), [32]byte{}); err == nil || !strings.HasPrefix(err.Error(), "encrypt: instantiating guest: ") {
		t.Errorf("seededClient over a bad build: %v, want the instance's error", err)
	}
	if isPinned(c, []byte("not wasm")) {
		t.Error("pinned a build that did not compile")
	}
}
