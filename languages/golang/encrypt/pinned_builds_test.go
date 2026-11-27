package encrypt

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// countingBuilds is a pinnedBuilds whose compile counts its calls, waits
// a moment so that concurrent callers overlap, and fails while fail is set.
func countingBuilds() (*pinnedBuilds, *atomic.Int32, *atomic.Bool) {
	var calls atomic.Int32
	var fail atomic.Bool
	p := &pinnedBuilds{compile: func(context.Context, []byte) (any, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		if fail.Load() {
			return nil, errCompile
		}
		return struct{}{}, nil
	}}
	return p, &calls, &fail
}

var errCompile = errors.New("compile failed")

// A test build compiles once in a process, however many clients start and
// close, one after another or at once. wazero drops a compiled module from
// its in-memory cache when the last runtime using it closes, so without the
// pin every client in a suite that starts one per test compiled the guest
// again: about ten seconds each under the race detector.
func TestPinnedBuilds(t *testing.T) {
	for _, tt := range []struct {
		name string
		run  func(t *testing.T, p *pinnedBuilds, fail *atomic.Bool)
		want int32
	}{
		{
			name: "one build pinned twice compiles once",
			run: func(t *testing.T, p *pinnedBuilds, _ *atomic.Bool) {
				pin(t, p, "a")
				pin(t, p, "a")
			},
			want: 1,
		},
		{
			name: "one build pinned at once by many callers compiles once",
			run: func(t *testing.T, p *pinnedBuilds, _ *atomic.Bool) {
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { pin(t, p, "a") })
				}
				wg.Wait()
			},
			want: 1,
		},
		{
			name: "each build compiles once",
			run: func(t *testing.T, p *pinnedBuilds, _ *atomic.Bool) {
				pin(t, p, "a")
				pin(t, p, "b")
				pin(t, p, "a")
			},
			want: 2,
		},
		{
			name: "a failed compile is not pinned",
			run: func(t *testing.T, p *pinnedBuilds, fail *atomic.Bool) {
				fail.Store(true)
				if err := p.pin(context.Background(), []byte("a")); !errors.Is(err, errCompile) {
					t.Fatalf("%v, want the compile's error", err)
				}
				fail.Store(false)
				pin(t, p, "a")
				pin(t, p, "a")
			},
			want: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, calls, fail := countingBuilds()
			tt.run(t, p, fail)
			if got := calls.Load(); got != tt.want {
				t.Fatalf("compiled %d times, want %d", got, tt.want)
			}
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
			testBuilds.mu.Lock()
			_, ok := testBuilds.pinned[sha256.Sum256(wasm)]
			testBuilds.mu.Unlock()
			if !ok {
				t.Fatal("seededClient did not pin the build it ran")
			}
		})
	}
}

func pin(t *testing.T, p *pinnedBuilds, wasm string) {
	t.Helper()
	if err := p.pin(context.Background(), []byte(wasm)); err != nil {
		t.Error(err)
	}
}

// The real compile, over the guest this package embeds: once a build is
// pinned, a runtime that compiles it reads the cache, even after every
// other runtime that used the build has closed. Without the pin, wazero
// drops the build from the cache when the first runtime closes, and the
// last compile below takes as long as a cold one.
func TestPinnedBuildsKeepTheGuestCompiled(t *testing.T) {
	wasm, err := plainGuest()
	if errors.Is(err, ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	var p pinnedBuilds
	if err := p.pin(context.Background(), []byte("not wasm")); err == nil {
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
	ctx := context.Background()
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

	if err := p.pin(context.Background(), wasm); err != nil {
		t.Fatal(err)
	}
	shared := wazero.NewRuntimeConfig().WithCompilationCache(compilationCache())
	compile(shared)
	if again := compile(shared); again > cold/4 {
		t.Fatalf("a compile after the pin took %v and a cold compile %v: the pinned build left the cache", again, cold)
	}
}

// encrypttest.AssertContexts and encrypttest.Contexts make a new checker
// on every call, and close it before they return. A checker over a test
// build compiles that build once in a process, however many are made and
// closed. Before, each call compiled the guest again: under the race
// detector, 10 to 50 seconds a call.
func TestTestCheckersCompileTheirBuildOnce(t *testing.T) {
	if _, err := plainGuest(); errors.Is(err, ErrGuestNotBuilt) {
		t.Skip(err)
	}
	var calls atomic.Int32
	builds := &pinnedBuilds{compile: func(ctx context.Context, wasm []byte) (any, error) {
		calls.Add(1)
		return compileForever(ctx, wasm)
	}}
	ctx := context.Background()
	plan := &record.Plan{
		Context: []string{"users"},
		Fields:  []record.Field{{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext}}},
	}
	for range 3 {
		// The same loader for both builds: whichever one selectBuild picks
		// in this binary, it is this build.
		checker, err := testChecker(ctx, builds, plainGuest, plainGuest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checker.Contexts(ctx, plan); err != nil {
			t.Fatal(err)
		}
		if err := checker.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("compiled %d times, want 1", got)
	}
}

// A test build that is not there is the loader's error, and nothing is
// compiled or kept.
func TestATestCheckerWithoutItsBuildIsTheLoadersError(t *testing.T) {
	builds, calls, _ := countingBuilds()
	missing := func() ([]byte, error) { return nil, errCompile }
	if _, err := testChecker(context.Background(), builds, missing, missing); !errors.Is(err, errCompile) {
		t.Fatalf("%v, want the loader's error", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("compiled %d times, want 0", got)
	}
}
