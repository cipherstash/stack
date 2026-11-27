package encrypt

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testclient"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// Package encrypttest builds its clients through this constructor. It is
// registered with internal/testclient, which only packages under encrypt can
// import, so no public function builds a client over a guest the caller
// chooses. It does nothing without a deterministic-kms build: the guests
// embedded for production refuse a bare seed as their config. It picks
// between the two test builds by selectBuild, the rule embeddedGuest uses.
func init() {
	testclient.Register(func(ctx context.Context, builds testclient.Builds, seed [32]byte) (any, error) {
		wasm, err := selectBuild(builds.Plain, builds.WithEQL)
		if err != nil {
			return nil, err
		}
		return seededClient(ctx, wasm, seed)
	}, func(ctx context.Context, builds testclient.Builds) (any, error) {
		return testChecker(ctx, builds)
	})
}

// testChecker is a checker over the test build selectBuild picks, the one
// a test client in this program runs. It pins that build in engines, as
// seededClient does, so that encrypttest.AssertContexts, which makes a
// checker on every call, compiles the guest once per test binary, and not
// on every call.
func testChecker(ctx context.Context, builds testclient.Builds) (*Checker, error) {
	wasm, err := selectBuild(builds.Plain, builds.WithEQL)
	if err != nil {
		return nil, err
	}
	engines.pin(ctx, wasm)
	return newCheckerOver(ctx, wasm)
}

// seededClient is a client over wasm, a deterministic-kms build of the
// guest. Its config is the 32-byte seed every key derives from. It has no
// token and a transport that refuses every request, so nothing it does can
// reach the network. It pins wasm in engines, so the test binary compiles
// it once, however many test clients start and close.
func seededClient(ctx context.Context, wasm []byte, seed [32]byte) (*Client, error) {
	engines.pin(ctx, wasm)
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
