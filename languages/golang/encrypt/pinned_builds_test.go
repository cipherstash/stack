package encrypt

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
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
	// The compiles below run on one worker, so a compile that misses the
	// cache takes about 20 times as long as one that reads it, on any
	// number of cores. With a worker for each core, a machine with many
	// cores compiles the guest only about 3 times slower than it reads it
	// from the cache, which is too close to tell apart.
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

	var p pinnedBuilds
	if err := p.pin(context.Background(), wasm); err != nil {
		t.Fatal(err)
	}
	shared := wazero.NewRuntimeConfig().WithCompilationCache(compilationCache())
	compile(shared)
	if again := compile(shared); again > cold/4 {
		t.Fatalf("a compile after the pin took %v and a cold compile %v: the pinned build left the cache", again, cold)
	}

	if err := p.pin(context.Background(), []byte("not wasm")); err == nil {
		t.Fatal("pinned bytes that are not a WebAssembly module")
	}
}
