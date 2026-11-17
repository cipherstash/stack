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
// chooses. It does nothing without a deterministic-kms build: the guest
// embedded for production refuses a bare seed as its config.
func init() {
	testclient.Register(func(ctx context.Context, wasm []byte, seed [32]byte) (any, error) {
		return seededClient(ctx, wasm, seed)
	})
}

// seededClient is a client over wasm, a deterministic-kms build of the
// guest. Its config is the 32-byte seed every key derives from. It has no
// token and a transport that refuses every request, so nothing it does can
// reach the network.
func seededClient(ctx context.Context, wasm []byte, seed [32]byte) (*Client, error) {
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
