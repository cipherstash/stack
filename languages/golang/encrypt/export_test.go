package encrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
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

// JSONOpensForTest asks se_json_open to open no rows of a read whose request
// names operator as its operation, at path: nil when the engine opens a
// read of that operation.
func (cph *Cipher) JSONOpensForTest(ctx context.Context, plan *record.Plan, field, operator, path string) error {
	_, err := cph.jsonOpen(ctx, plan, field, vcvalue.Object{{Key: "operation", Value: operator}, {Key: "path", Value: path}}, nil)
	return err
}

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
// run wasm:guest:build:deterministic` writes where package encrypttest embeds
// it. This package's tests read it from disk: encrypttest imports encrypt,
// so they cannot import encrypttest.
const deterministicGuestPath = "encrypttest/wasm/stack_encrypt_guest_deterministic.wasm"

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
	return seededClient(ctx, wasm, seed)
}

// ErrDeterministicEQLGuestNotBuilt says the test build with the EQL types
// is absent, or package eql is not linked.
var ErrDeterministicEQLGuestNotBuilt = errors.New("encrypt: deterministic eql guest not built; run `mise run wasm:guest:build:eql:deterministic`")

// deterministicEQLGuestPath is the test build WITH the EQL types, which
// `mise run wasm:guest:build:eql:deterministic` writes beside the other.
const deterministicEQLGuestPath = "encrypttest/wasm/stack_encrypt_guest_eql_deterministic.wasm"

// NewDeterministicEQLClient is NewDeterministicClient over the test build
// WITH the EQL types.
func NewDeterministicEQLClient(ctx context.Context, seed [32]byte) (*Client, error) {
	wasm, err := os.ReadFile(deterministicEQLGuestPath)
	if err != nil {
		return nil, ErrDeterministicEQLGuestNotBuilt
	}
	return seededClient(ctx, wasm, seed)
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
	opts := cph.dataKeyCall()
	opts.context = cph.context
	return cph.client.openTree(ctx, opts, p, tree)
}

// OpenTreeForTest deliberately bypasses host plan validation to observe the
// uninitialised guest's preflight, including plans the host refuses earlier.
func (k *Checker) OpenTreeForTest(ctx context.Context, tree []any, plan *record.Plan, expected string) ([]record.Source, error) {
	return k.c.openTree(ctx, callOptions{keyset: k.c.DefaultKeyset().keyset, context: expected}, plan, tree)
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
	opts := cph.dataKeyCall()
	opts.context = cph.context
	return cph.client.openEncoded(ctx, opts, p, encoded, rows)
}

// OpenFrameForTest is the uninitialised guest's view of the same batch: its
// preflight on the raw bytes, before any cipher exists.
func (k *Checker) OpenFrameForTest(ctx context.Context, encoded []byte, rows int, plan *record.Plan, expected string) ([]record.Source, error) {
	return k.c.openEncoded(ctx, callOptions{keyset: k.c.DefaultKeyset().keyset, context: expected}, plan, encoded, rows)
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

// RecordedRequest is one request a client sent to ZeroKMS: its URL path and
// its body.
type RecordedRequest struct {
	Path string
	Body []byte
}

// RecordRequests makes c record every request it sends to ZeroKMS from now
// on. The returned function gives the requests recorded since its last
// call. A test uses it to read what a call sent, such as the audit metadata
// of a data-key request. Call it before the client's first call under test,
// and not while a call is running.
func RecordRequests(c *Client) func() []RecordedRequest {
	recorder := &recordingTransport{next: c.transport.rt}
	c.transport.rt = recorder
	return recorder.take
}

type recordingTransport struct {
	next     http.RoundTripper
	mu       sync.Mutex
	requests []RecordedRequest
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.requests = append(r.requests, RecordedRequest{Path: req.URL.Path, Body: bytes.Clone(body)})
		r.mu.Unlock()
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return r.next.RoundTrip(req)
}

func (r *recordingTransport) take() []RecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	taken := r.requests
	r.requests = nil
	return taken
}

// TermWithAuditForTest sends the guest a term call whose options carry
// audit metadata, which no call of the SDK does: a term asks for no data
// key, so the SDK leaves the metadata out. The test reads what the guest
// answers to a host that sends it anyway.
func (cph *Cipher) TermWithAuditForTest(ctx context.Context, value any, fieldContext []any) ([]byte, error) {
	encodedValue, err := vcffi.Marshal(value)
	if err != nil {
		return nil, err
	}
	encodedContext, err := vcffi.Marshal(fieldContext)
	if err != nil {
		return nil, err
	}
	code, _ := termKindCode(record.Equality)
	// The options of a data-key call, on a term call: the metadata rides
	// where the SDK never puts it.
	opts, err := cph.dataKeyCall().marshal()
	if err != nil {
		return nil, err
	}
	return cph.client.callKMS(ctx, func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.term, buf(encodedValue), buf(encodedContext), scalar(uint64(code)), buf(opts))
	})
}

// AuditFactsForTest is the audit metadata the cipher holds, as the guest
// receives it: the options object's "audit" value, through the transport
// codec. nil for a cipher that sends none. A refusal the cipher holds, which
// its first call would report, is the error.
func (cph *Cipher) AuditFactsForTest() (any, error) {
	if cph.err != nil {
		return nil, cph.err
	}
	facts, ok := cph.dataKeyCall().wire()["audit"]
	if !ok {
		return nil, nil
	}
	encoded, err := vcffi.Marshal(facts)
	if err != nil {
		return nil, err
	}
	return vcffi.Unmarshal(encoded)
}

// AuditUncheckedForTest is the cipher with facts as its audit metadata, as
// given and with no check. The builder cannot build a value that ZeroKMS
// has no form for, so a test uses this to send the guest one anyway: an
// integer above the largest int64, or bytes. The guest then refuses the
// call, which also shows that the call sent its metadata.
func (cph *Cipher) AuditUncheckedForTest(facts map[string]any) *Cipher {
	next := cph.copy()
	next.audit = func() map[string]any { return facts }
	return next
}
