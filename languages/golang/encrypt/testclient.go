package encrypt

import (
	"context"
	"crypto/sha256"
	"fmt"
	goruntime "runtime"
	"sync"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testclient"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/experimental"
)

// Package encrypttest builds its clients through this constructor. It is
// registered with internal/testclient, which only packages under encrypt can
// import, so no public function builds a client over a guest the caller
// chooses. It does nothing without a deterministic-kms build: the guests
// embedded for production refuse a bare seed as their config. It picks
// between the two test builds by selectBuild, the rule embeddedGuest uses.
func init() {
	testclient.Register(func(ctx context.Context, plain, withEQL func() ([]byte, error), seed [32]byte) (any, error) {
		wasm, err := selectBuild(plain, withEQL)
		if err != nil {
			return nil, err
		}
		return seededClient(ctx, wasm, seed)
	}, func(ctx context.Context, plain, withEQL func() ([]byte, error)) (any, error) {
		return testChecker(ctx, &testBuilds, plain, withEQL)
	})
}

// testChecker is a checker over the test build selectBuild picks, the one
// a test client in this program runs. builds keeps that build compiled, so
// that encrypttest.AssertContexts, which makes a checker on every call,
// compiles the guest once per test binary, and not on every call.
func testChecker(ctx context.Context, builds *pinnedBuilds, plain, withEQL func() ([]byte, error)) (*Checker, error) {
	wasm, err := selectBuild(plain, withEQL)
	if err != nil {
		return nil, err
	}
	if err := builds.pin(ctx, wasm); err != nil {
		return nil, err
	}
	return newCheckerOver(ctx, wasm)
}

// seededClient is a client over wasm, a deterministic-kms build of the
// guest. Its config is the 32-byte seed every key derives from. It has no
// token and a transport that refuses every request, so nothing it does can
// reach the network.
func seededClient(ctx context.Context, wasm []byte, seed [32]byte) (*Client, error) {
	if err := testBuilds.pin(ctx, wasm); err != nil {
		return nil, err
	}
	tr := &transport{rt: refusingTransport{}, token: noToken{}}
	inst, err := newInstance(ctx, wasm, tr, guest.BestEffort)
	if err != nil {
		return nil, err
	}
	c := newClient(inst, tr)
	encoded, err := vcffi.Marshal(seed[:])
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	out, err := c.call(ctx, func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.cipherInit, buf(encoded))
	})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("encrypt: deterministic cipher init: %w", err)
	}
	if len(out) != len(KeysetID{}) {
		_ = c.Close()
		return nil, fmt.Errorf("%w: cipher init returned %d bytes for the keyset id", ErrInternal, len(out))
	}
	copy(c.def[:], out)
	return c, nil
}

// testBuilds holds every test build a test client or checker has run,
// compiled.
var testBuilds pinnedBuilds

// pinnedBuilds keeps each guest build it is given compiled in the shared
// compilation cache for the life of the process, so that test clients and
// checkers compile the guest once per test binary.
//
// wazero counts the runtimes that use a compiled module in its in-memory
// cache, and deletes the module when the last of them closes. A suite that
// starts a client in each test, and closes it when the test ends, would
// compile the guest again in every test: about one second each, and about
// ten under the race detector. Parallel tests that start clients at once
// would each compile it too. pin compiles each build once, on a runtime it
// never closes, so the count never reaches zero. That copy is never
// instantiated: every client still compiles on its own runtime, and reads
// the compiled code from the cache.
type pinnedBuilds struct {
	mu     sync.Mutex
	pinned map[[sha256.Size]byte]any
	// compile compiles wasm into the shared cache and returns what keeps
	// it there. nil is compileForever; tests replace it.
	compile func(ctx context.Context, wasm []byte) (any, error)
}

// pin compiles wasm into the shared cache the first time it is given, and
// keeps it there. Callers given the same build at once wait for one
// compile. A compile that fails is not kept, so the next caller tries again.
func (p *pinnedBuilds) pin(ctx context.Context, wasm []byte) error {
	key := sha256.Sum256(wasm)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.pinned[key]; ok {
		return nil
	}
	compile := p.compile
	if compile == nil {
		compile = compileForever
	}
	kept, err := compile(ctx, wasm)
	if err != nil {
		return err
	}
	if p.pinned == nil {
		p.pinned = map[[sha256.Size]byte]any{}
	}
	p.pinned[key] = kept
	return nil
}

// compileForever compiles wasm on a runtime that is never closed, with
// guestRuntimeConfig, the configuration newInstance uses, so the module
// has the cache entry a client looks up. It compiles the guest's
// functions on every core: the compiled code is the same, and under the
// race detector the compile takes about ten seconds on one core.
func compileForever(ctx context.Context, wasm []byte) (any, error) {
	runtime := wazero.NewRuntimeWithConfig(ctx, guestRuntimeConfig())
	compiled, err := runtime.CompileModule(experimental.WithCompilationWorkers(ctx, goruntime.GOMAXPROCS(0)), wasm)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("encrypt: compiling the test build: %w", err)
	}
	return compiled, nil
}
