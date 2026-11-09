package encrypt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/tetratelabs/wazero/api"
)

// The test-only ways to give a client a token. The public API takes tokens
// only from auth strategies; the tests that talk to httptest stubs
// need a fixed one, and get it here rather than through anything a caller
// could reach.

// tokenFunc adapts a function to a tokenSource.
type tokenFunc func(ctx context.Context) (string, error)

func (f tokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// staticToken is a tokenSource that always returns token.
func staticToken(token string) tokenSource {
	return tokenFunc(func(context.Context) (string, error) { return token, nil })
}

// newTestCredentials is NewCredentials with token in place of a strategy:
// the same type, so the same consume-on-refusal and no-Close semantics.
// A nil token is refused as NewCredentials refuses a nil strategy.
func newTestCredentials(clientID string, key *ClientKey, token tokenSource) Credentials {
	return &explicitCredentials{clientID: clientID, key: key, token: token}
}

// withZeroKMSURL points the client at a ZeroKMS stub. There is no public
// option for it: applications take the endpoint from the token, or from
// CS_ZEROKMS_HOST.
func withZeroKMSURL(url string) ClientOption {
	return func(o *clientOptions) { o.zerokmsURL = url }
}

// The hooks the external tests (package encrypt_test, which can import the
// generated test types this package cannot) reach the internals through.

// WithZeroKMSURL is withZeroKMSURL for the external tests.
func WithZeroKMSURL(url string) ClientOption { return withZeroKMSURL(url) }

// Sends is how many ZeroKMS requests the client has made.
func Sends(c *Client) int64 { return c.transport.sends.Load() }

// ResetSends zeroes the count.
func ResetSends(c *Client) { c.transport.sends.Store(0) }

// GuestMemory is a copy of the guest's linear memory, for residency scans.
func GuestMemory(t *testing.T, c *Client) []byte {
	t.Helper()
	mem := c.inst.module.Memory()
	view, ok := mem.Read(0, mem.Size())
	if !ok {
		t.Fatal("cannot read guest memory")
	}
	return append([]byte(nil), view...)
}

// deterministicGuestPath is the deterministic-kms test build, which `mise
// run wasm:guest:build:deterministic` writes under testdata: a directory
// `go build` and the package's `//go:embed wasm` ignore, so the test build
// is read from disk here and embedded in no binary.
const deterministicGuestPath = "testdata/stack_encrypt_guest_deterministic.wasm"

// ErrDeterministicGuestNotBuilt says the test build is absent.
var ErrDeterministicGuestNotBuilt = errors.New("encrypt: deterministic guest not built; run `mise run wasm:guest:build:deterministic`")

// NewDeterministicClient is a client over the deterministic-kms test build
// of the guest, seeded: every key derives from the seed and the context, so
// it opens what the Rust record fixture sealed under the same seed and
// needs no ZeroKMS. ErrDeterministicGuestNotBuilt when the build is absent.
// This is the build WITHOUT the EQL types, whatever is linked: the tests
// name the build they run against (NewDeterministicEQLClient is the other),
// so each build keeps its own coverage.
func NewDeterministicClient(ctx context.Context, seed [32]byte) (*Client, error) {
	wasm, err := DeterministicGuest()
	if err != nil {
		return nil, err
	}
	return deterministicClient(ctx, wasm, seed)
}

// ErrDeterministicEQLGuestNotBuilt says the test build with the EQL types
// is absent, or package eql is not linked.
var ErrDeterministicEQLGuestNotBuilt = errors.New("encrypt: deterministic eql guest not built; run `mise run wasm:guest:build:eql:deterministic`")

// deterministicEQLGuestPath is the test build WITH the EQL types, which
// `mise run wasm:guest:build:eql:deterministic` writes under testdata too.
const deterministicEQLGuestPath = "testdata/stack_encrypt_guest_eql_deterministic.wasm"

// NewDeterministicEQLClient is NewDeterministicClient over the test build
// WITH the EQL types.
func NewDeterministicEQLClient(ctx context.Context, seed [32]byte) (*Client, error) {
	wasm, err := os.ReadFile(deterministicEQLGuestPath)
	if err != nil {
		return nil, ErrDeterministicEQLGuestNotBuilt
	}
	return deterministicClient(ctx, wasm, seed)
}

func deterministicClient(ctx context.Context, wasm []byte, seed [32]byte) (*Client, error) {
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

// NewDeterministicVendorClient is NewDeterministicClient with a key vendor
// backend beside the seeded ZeroKMS stand-in: the deterministic build's
// object config, {"seed", key_vendor, keyset_records, ...}. Vendor requests
// go to rt, and their credentials come from the backend's source through
// the real step loop. The StaticKey, if any, is wiped as NewClient wipes
// it.
func NewDeterministicVendorClient(ctx context.Context, seed [32]byte, rt http.RoundTripper, v KeyVendor, records ...string) (*Client, error) {
	defer wipeVendorKey(v)
	wasm, err := os.ReadFile(deterministicGuestPath)
	if err != nil {
		return nil, ErrDeterministicGuestNotBuilt
	}
	spec, err := keyVendorConfig(v, records)
	if err != nil {
		return nil, err
	}
	fields := vcvalue.Object{{Key: "seed", Value: seed[:]}}
	if spec != nil {
		fields = append(fields, spec.configFields(records)...)
	}
	encoded, err := vcffi.Marshal(fields)
	if err != nil {
		return nil, err
	}
	defer wipe(encoded)
	tr := &transport{rt: rt, token: noToken{}, vendor: spec}
	inst, err := newInstance(ctx, wasm, tr, guest.BestEffort)
	if err != nil {
		return nil, err
	}
	c := newClient(inst, tr)
	out, err := c.call(ctx, func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.cipherInit, buf(encoded))
	})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("encrypt: deterministic cipher init: %w", err)
	}
	copy(c.def[:], out)
	return c, nil
}

// RawClient is a guest that was never given a client key: every well-formed
// operation is ErrState, every malformed one ErrEncoding, and the checker
// exports work.
func RawClient(t *testing.T, wasm []byte) *Client {
	t.Helper()
	inst, err := newInstance(context.Background(), wasm, &transport{rt: http.DefaultTransport, token: staticToken("t")}, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(inst, nil)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// EmbeddedGuest is the guest a client runs: the build with the EQL types
// when package eql is linked (it is, by the generated test types), else
// this package's own. ErrGuestNotBuilt when absent.
func EmbeddedGuest() ([]byte, error) { return embeddedGuest() }

// PlainGuest is this package's own embedded guest, the build without the
// EQL types, whatever is linked. ErrGuestNotBuilt when absent.
func PlainGuest() ([]byte, error) {
	wasm, err := guestFS.ReadFile(guestPath)
	if err != nil {
		return nil, ErrGuestNotBuilt
	}
	return wasm, nil
}

// NewCheckerOver is NewChecker over the given guest bytes, so a test asks a
// named build its questions.
func NewCheckerOver(ctx context.Context, wasm []byte) (*Checker, error) {
	t := &transport{rt: refusingTransport{}, token: noToken{}}
	inst, err := newInstance(ctx, wasm, t, guest.BestEffort)
	if err != nil {
		return nil, err
	}
	return &Checker{c: newClient(inst, t)}, nil
}

// LiveClient is liveClient for the external tests: a client against real
// ZeroKMS from the STACK_ENCRYPT_TEST_* variables, or a skip.
func LiveClient(t *testing.T) *Client { return liveClient(t) }

// WantDiagnostic asserts that err carries a *Diagnostic with code and a
// message, and returns it; WantCode only asserts.
var (
	WantDiagnostic = wantDiagnostic
	WantCode       = wantCode
)

// CheckFrameForTest reaches the engine parser without host Plan validation or
// lowering, so the shared grammar can include malformed declarations. The
// checker has no cipher, credentials or usable transport.
func (k *Checker) CheckFrameForTest(ctx context.Context, encoded []byte) error {
	return k.checkFrame(ctx, encoded)
}

// DeterministicGuest reads the named test build without embedding it.
func DeterministicGuest() ([]byte, error) {
	wasm, err := os.ReadFile(deterministicGuestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrDeterministicGuestNotBuilt
	}
	return wasm, err
}

// OpenTreeForTest accepts stored shapes that record.Sealed cannot express,
// while preserving Cipher validation, extension, context and production decoding.
func (cph *Cipher) OpenTreeForTest(ctx context.Context, tree []any, plan *record.Plan) ([]record.Source, error) {
	if cph == nil {
		return nil, fmt.Errorf("%w: Open on a nil *Cipher", ErrEncoding)
	}
	p, err := cph.plan(plan)
	if err != nil {
		return nil, err
	}
	return cph.client.openTree(ctx, cph.keyset, cph.context, p, tree)
}

// OpenTreeForTest deliberately bypasses host plan validation to observe the
// uninitialised guest's preflight, including plans the host refuses earlier.
func (k *Checker) OpenTreeForTest(ctx context.Context, tree []any, plan *record.Plan, expected string) ([]record.Source, error) {
	return k.c.openTree(ctx, k.c.DefaultKeyset().keyset, expected, plan, tree)
}

// OpenFrameForTest hands the guest a stored batch already in the transport
// codec, so a test can send what the tree encoder refuses to write (a
// repeated key, a malformed leaf). rows is the batch's record count. Cipher
// validation, scope, context and production decoding are kept.
func (cph *Cipher) OpenFrameForTest(ctx context.Context, encoded []byte, rows int, plan *record.Plan) ([]record.Source, error) {
	if cph == nil {
		return nil, fmt.Errorf("%w: Open on a nil *Cipher", ErrEncoding)
	}
	p, err := cph.plan(plan)
	if err != nil {
		return nil, err
	}
	return cph.client.openEncoded(ctx, cph.keyset, cph.context, p, encoded, rows)
}

// OpenFrameForTest is the uninitialised guest's view of the same batch: its
// preflight on the raw bytes, before any cipher exists.
func (k *Checker) OpenFrameForTest(ctx context.Context, encoded []byte, rows int, plan *record.Plan, expected string) ([]record.Source, error) {
	return k.c.openEncoded(ctx, k.c.DefaultKeyset().keyset, expected, plan, encoded, rows)
}

// ObserveEncryptPlansForTest copies the actual plan buffer at the WASM call
// boundary. Install and restore only while this test's client is idle.
func ObserveEncryptPlansForTest(c *Client, observe func([]byte)) func() {
	original := c.inst.encryptRecord
	c.inst.encryptRecord = &observedEncryptCall{Function: original, module: c.inst.module, observe: observe}
	return func() { c.inst.encryptRecord = original }
}

type observedEncryptCall struct {
	api.Function
	module  api.Module
	observe func([]byte)
}

func (f *observedEncryptCall) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	// se_encrypt_record(source_ptr, source_len, plan_ptr, plan_len, opts_ptr, opts_len).
	if len(params) != 6 {
		return nil, fmt.Errorf("unexpected encrypt ABI: %d arguments", len(params))
	}
	plan, ok := f.module.Memory().Read(uint32(params[2]), uint32(params[3]))
	if !ok {
		return nil, errors.New("plan outside guest memory")
	}
	f.observe(append([]byte(nil), plan...))
	return f.Function.Call(ctx, params...)
}

// UnmarshalCipherTextForTest decodes a stored batch with the host's tree
// codec, so a test can show that a frame the guest refuses is one the host
// could never have written either.
func UnmarshalCipherTextForTest(buf []byte) (any, error) { return unmarshalCipherText(buf) }
