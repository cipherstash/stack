package stackencrypt

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/sys"
)

// Tests that drive the embedded guest without a live ZeroKMS. What they
// pin, hermetically:
//
//   - the module's import surface is exactly WASI plus the two transport
//     functions;
//   - the bridge issues the request ZeroKMS expects and maps every
//     transport/HTTP outcome to the documented error;
//   - every encoding this package builds — config, selectors, options,
//     values, plans, sources, record trees, term inputs — is accepted by
//     the guest's parsers. The guest validates all inputs before it
//     consults its cipher, so on an instance that was never initialised a
//     well-formed call is ErrState and a malformed one is ErrEncoding: the
//     status tells which side of the boundary is wrong, with no key
//     material involved;
//   - hostile pointer/length pairs are statuses, never traps;
//   - the client key does not survive in guest memory.
//
// Round trips through real key material need ZeroKMS and live in
// live_test.go (skipped without credentials; phase 5's harness runs them).

const (
	testClientID = "6a70bd18-99ac-4650-b104-37eec3a15b09"
	// A generated v1 client key (a recipher proxy keyset, CBOR, hex) with no
	// ZeroKMS behind it: the guest parses it, and it is distinctive enough
	// for the residency scan.
	testClientKey = "a4627031a16b7065726d75746174696f6e90090a0d070806020f0e010503040b0c006770325f66726f6da16b7065726d75746174696f6e90000e08070c030a01050d06040f0b09026570325f746fa16b7065726d75746174696f6e9005030c0f060702000e010a0b0804090d627033a16b7065726d75746174696f6e982102010c0a182008181b061116120b070f10051509181c0d131403181a0e181d18180400181f17181e1819"
)

func guestOrSkip(t *testing.T) []byte {
	t.Helper()
	wasm, err := embeddedGuest()
	if err != nil {
		t.Skipf("%v", err)
	}
	return wasm
}

// zerokmsStub records the requests a client makes and answers them all with
// one canned response.
type zerokmsStub struct {
	*httptest.Server
	requests []stubRequest
	status   int
	body     string
	// contentType "" means the header is absent (Go's sniffing suppressed).
	contentType string
}

type stubRequest struct {
	method, path, auth, contentType, body string
}

func newStub(t *testing.T, status int, contentType, body string) *zerokmsStub {
	t.Helper()
	s := &zerokmsStub{status: status, body: body, contentType: contentType}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.requests = append(s.requests, stubRequest{
			method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"), body: string(b),
		})
		if s.contentType == "" {
			w.Header()["Content-Type"] = nil
		} else {
			w.Header().Set("Content-Type", s.contentType)
		}
		w.WriteHeader(s.status)
		_, _ = io.WriteString(w, s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func testConfig(url string) Config {
	return Config{
		ClientID:   testClientID,
		ClientKey:  testClientKey,
		ZeroKMSURL: url,
		Token:      StaticToken("stub-token"),
	}
}

func TestImportSurfaceIsWASIPlusTransport(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	compiled, err := r.CompileModule(ctx, guestOrSkip(t))
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close(ctx)
	var transportImports []string
	for _, imp := range compiled.ImportedFunctions() {
		module, name, _ := imp.Import()
		switch module {
		case "wasi_snapshot_preview1":
			for _, denied := range []string{"path_", "sock_", "fd_prestat"} {
				if strings.HasPrefix(name, denied) {
					t.Errorf("guest imports capability-granting WASI function %s", name)
				}
			}
		case transportModule:
			transportImports = append(transportImports, name)
		default:
			t.Errorf("guest imports %s::%s, outside the allowed surface", module, name)
		}
	}
	want := []string{"token_get", "transport_send"}
	sort.Strings(transportImports)
	if !reflect.DeepEqual(transportImports, want) {
		t.Fatalf("transport imports = %v, want %v", transportImports, want)
	}
	for name := range map[string]bool{"se_alloc": true, "se_dealloc": true, "se_cipher_init": true, "se_shutdown": true, "se_keyset": true, "se_encrypt": true, "se_decrypt": true, "se_encrypt_element": true, "se_decrypt_element": true, "se_term": true, "se_encrypt_record": true, "se_decrypt_record": true} {
		if _, ok := compiled.ExportedFunctions()[name]; !ok {
			t.Errorf("guest does not export %s", name)
		}
	}
}

func TestNewClientIssuesTheLoadKeysetRequest(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	_, err := NewClient(context.Background(), testConfig(stub.URL))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized", err)
	}
	if len(stub.requests) != 1 {
		t.Fatalf("requests = %d, want 1 (one load-keyset)", len(stub.requests))
	}
	req := stub.requests[0]
	if req.method != http.MethodPost || req.auth != "Bearer stub-token" || req.contentType != "application/json" {
		t.Errorf("request = %+v", req)
	}
	if !strings.HasSuffix(req.path, "load-keyset") {
		t.Errorf("path = %q, want a load-keyset endpoint", req.path)
	}
	if !strings.HasPrefix(req.body, "{") {
		t.Errorf("body %q is not JSON", req.body)
	}
	if strings.Contains(req.body, testClientKey) {
		t.Error("the client key was sent over the wire")
	}
}

func TestTransportOutcomesMapToErrors(t *testing.T) {
	guestOrSkip(t)
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        error
	}{
		{"401", http.StatusUnauthorized, "", "nope", ErrUnauthorized},
		{"403", http.StatusForbidden, "", "not permitted", ErrForbidden},
		{"404", http.StatusNotFound, "", "missing", ErrNotFound},
		{"409", http.StatusConflict, "", "exists", ErrConflict},
		{"500", http.StatusInternalServerError, "", "boom", ErrKMS},
		{"200 html", http.StatusOK, "text/html", "<html>gateway</html>", ErrKMS},
		{"200 not json", http.StatusOK, "application/json", "not json", ErrKMS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStub(t, tc.status, tc.contentType, tc.body)
			_, err := NewClient(context.Background(), testConfig(stub.URL))
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewClient: %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("connection refused", func(t *testing.T) {
		stub := newStub(t, http.StatusOK, "application/json", "{}")
		url := stub.URL
		stub.Close()
		_, err := NewClient(context.Background(), testConfig(url))
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("NewClient: %v, want ErrTransport", err)
		}
	})
	t.Run("no token", func(t *testing.T) {
		stub := newStub(t, http.StatusOK, "application/json", "{}")
		cfg := testConfig(stub.URL)
		cfg.Token = TokenFunc(func(context.Context) (string, error) { return "", errors.New("vault down") })
		_, err := NewClient(context.Background(), cfg)
		if err == nil {
			t.Fatal("NewClient succeeded with no token")
		}
		if len(stub.requests) != 0 {
			t.Fatalf("a request was made without a token: %+v", stub.requests)
		}
	})
}

func TestRoundTripperFailureIsTransport(t *testing.T) {
	guestOrSkip(t)
	cfg := testConfig("http://zerokms.invalid")
	cfg.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no route")
	})
	_, err := NewClient(context.Background(), cfg)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("NewClient: %v, want ErrTransport", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An interrupted call closes the module (WithCloseOnContextDone); the
// client must then be closed rather than a wedge or a runtime error.
func TestInterruptedCallClosesTheClient(t *testing.T) {
	t.Run("deadline during a request", func(t *testing.T) {
		guestOrSkip(t)
		cfg := testConfig("http://zerokms.invalid")
		cfg.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := NewClient(ctx, cfg)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("NewClient: %v, want the deadline", err)
		}
	})
	t.Run("closed module is ErrState", func(t *testing.T) {
		ctx := context.Background()
		c := rawInstance(t)
		// What the runtime does to the module when a call's context ends.
		if err := c.inst.module.CloseWithExitCode(ctx, sys.ExitCodeContextCanceled); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Keyset(KeysetName("k")).KeysetID(ctx); !errors.Is(err, ErrState) {
			t.Fatalf("Keyset on a closed module: %v, want ErrState", err)
		}
		if err := c.Close(ctx); err != nil {
			t.Fatalf("Close after interruption: %v", err)
		}
		// The close must reach the runtime. An interrupted call closes the
		// module and marks the client closed; a Close that treated that as
		// "already done" would leave the runtime and the host module it
		// carries allocated for the life of the process.
		if !c.released {
			t.Error("Close after interruption left the runtime unreleased")
		}
		if m := c.inst.runtime.Module(transportModule); m != nil {
			t.Errorf("host module %s is still registered after Close", transportModule)
		}
		// Still idempotent.
		if err := c.Close(ctx); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})
}

// A response the host would have to buffer without bound is refused as a
// transport failure, whether the size is announced or streamed.
func TestOversizedResponseIsTransport(t *testing.T) {
	guestOrSkip(t)
	respond := func(length int64, body io.Reader) roundTripFunc {
		return func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": {"application/json"}},
				ContentLength: length,
				Body:          io.NopCloser(body),
			}, nil
		}
	}
	for name, rt := range map[string]roundTripFunc{
		"announced": respond(maxResponseBytes+1, strings.NewReader("{}")),
		"streamed":  respond(-1, io.MultiReader(strings.NewReader("{"), &zeros{n: maxResponseBytes})),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig("http://zerokms.invalid")
			cfg.Transport = rt
			_, err := NewClient(context.Background(), cfg)
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("NewClient: %v, want ErrTransport", err)
			}
		})
	}
}

// A bare empty part is an empty context, which the guest refuses at the
// boundary — so the constructor refuses it first, rather than handing back
// a Context that fails every call it is used in. A list is empty only when
// every part is, so With may still carry one.
func TestEmptyContextIsRefusedAtTheRoot(t *testing.T) {
	for name, part := range map[string]any{"string": "", "bytes": []byte{}} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewContext(part); err == nil {
				t.Fatal("NewContext accepted an empty part")
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("MustContext did not panic on an empty part")
					}
				}()
				_ = MustContext(part)
			}()
		})
	}
	// The rule is the tree's: an empty part beside a non-empty one is a
	// context the guest takes, so With must not inherit the root's check.
	mixed, err := MustContext("users/age").With("")
	if err != nil {
		t.Fatalf("With(empty): %v", err)
	}
	guestOrSkip(t)
	ctx := context.Background()
	// No cipher on a raw instance, so a context the guest accepts reaches
	// the state check — ErrState here means the context itself passed,
	// where a refused one is ErrEncoding before it.
	if _, err := rawInstance(t).DefaultKeyset().Term(ctx, uint32(34), mixed, Equality); !errors.Is(err, ErrState) {
		t.Fatalf("Term under [non-empty, empty]: %v, want ErrState (the context accepted)", err)
	}
}

// A body that fails partway through is a transport failure, not a partial
// response the guest is handed. io.ReadAll returns the bytes it managed to
// read alongside the error; those bytes are a fragment of a ZeroKMS reply
// and are wiped before the error goes back (see transport.perform) — the
// wipe is not observable from here, but the verdict is.
func TestInterruptedResponseBodyIsTransport(t *testing.T) {
	guestOrSkip(t)
	cfg := testConfig("http://zerokms.invalid")
	cfg.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/json"}},
			ContentLength: -1,
			Body: io.NopCloser(io.MultiReader(
				strings.NewReader(`{"partial":"`),
				&failingReader{err: io.ErrUnexpectedEOF},
			)),
		}, nil
	})
	if _, err := NewClient(context.Background(), cfg); !errors.Is(err, ErrTransport) {
		t.Fatalf("NewClient: %v, want ErrTransport", err)
	}
}

// A RoundTripper may keep reading the request body, and close it, in
// another goroutine after RoundTrip has returned — on the error path too.
// The host copy of the body must therefore survive until the transport
// closes it: a wipe on RoundTrip's return would race the send and put a
// truncated or zeroed request on the wire. Here the drain happens strictly
// after the whole guest call has returned, and must still see the request.
func TestRequestBodyOutlivesTheRoundTrip(t *testing.T) {
	guestOrSkip(t)
	returned := make(chan struct{})
	type drained struct {
		req  *http.Request
		body []byte
		err  error
	}
	done := make(chan drained, 1)
	cfg := testConfig("http://zerokms.invalid")
	cfg.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		go func() {
			<-returned
			b, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			done <- drained{req: r, body: b, err: err}
		}()
		return nil, errors.New("connection reset")
	})
	_, err := NewClient(context.Background(), cfg)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("NewClient: %v, want ErrTransport", err)
	}
	close(returned)
	d := <-done
	if d.err != nil {
		t.Fatalf("reading the body after RoundTrip returned: %v", d.err)
	}
	if !json.Valid(d.body) || !bytes.Contains(d.body, []byte(testClientID)) {
		t.Fatalf("body read after RoundTrip returned is not the request: %q", d.body)
	}
	// The length is declared, so the transport sends Content-Length rather
	// than chunking a body it cannot size.
	if d.req.ContentLength != int64(len(d.body)) {
		t.Errorf("ContentLength = %d, want %d", d.req.ContentLength, len(d.body))
	}
	// And once closed, the host copy is gone.
	rb, ok := d.req.Body.(*requestBody)
	if !ok {
		t.Fatalf("request body is %T, want *requestBody", d.req.Body)
	}
	if !bytes.Equal(rb.buf, make([]byte, len(rb.buf))) {
		t.Error("request body was not wiped on Close")
	}
}

// failingReader fails every read.
type failingReader struct{ err error }

func (f *failingReader) Read([]byte) (int, error) { return 0, f.err }

// zeros reads n zero bytes.
type zeros struct{ n int }

func (z *zeros) Read(p []byte) (int, error) {
	if z.n == 0 {
		return 0, io.EOF
	}
	if len(p) > z.n {
		p = p[:z.n]
	}
	clear(p)
	z.n -= len(p)
	return len(p), nil
}

func TestConfigValidation(t *testing.T) {
	ctx := context.Background()
	for name, cfg := range map[string]Config{
		"no token":     {ClientID: testClientID, ClientKey: testClientKey},
		"no client id": {ClientKey: testClientKey, Token: StaticToken("t")},
		"no key":       {ClientID: testClientID, Token: StaticToken("t")},
		"negative cache": {ClientID: testClientID, ClientKey: testClientKey, Token: StaticToken("t"),
			KeysetCacheSize: -1},
	} {
		if _, err := NewClient(ctx, cfg); err == nil {
			t.Errorf("%s: NewClient succeeded", name)
		}
	}
	// Malformed values the guest refuses: no request is made.
	guestOrSkip(t)
	for name, mutate := range map[string]func(*Config){
		"client id not a uuid": func(c *Config) { c.ClientID = "acme" },
		"key not hex":          func(c *Config) { c.ClientKey = "zz" },
		"bad url":              func(c *Config) { c.ZeroKMSURL = "not a url" },
	} {
		stub := newStub(t, http.StatusOK, "application/json", "{}")
		cfg := testConfig(stub.URL)
		mutate(&cfg)
		_, err := NewClient(ctx, cfg)
		if !errors.Is(err, ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
		}
		if len(stub.requests) != 0 {
			t.Errorf("%s: a request was made for a malformed config", name)
		}
	}
}

// rawInstance is a guest that was never initialised: every well-formed
// operation is ErrState there, every malformed one ErrEncoding.
func rawInstance(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	inst, err := newInstance(ctx, guestOrSkip(t), &transport{rt: http.DefaultTransport, token: StaticToken("t")})
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{inst: inst, transport: nil}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// A structurally valid stack-encrypt leaf (the frozen layout: version,
// keyset id, IV, tag length, tag, ciphertext) with no real key behind it.
var fixtureLeaf = mustHex("016b65797365742d666978747572653136303132333435363738396162636465660300aabbccdeadbeef")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type recordRow struct {
	Age   uint32 `stash:"context=users/age,index=eq;ore"`
	Email string `stash:"context=users/email,index=eq;match"`
}

// Every encoding the package builds reaches the guest's own parsers and
// passes them: the uninitialised instance answers ErrState only after it
// has validated all inputs.
func TestGuestAcceptsEveryEncodingThisPackageBuilds(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	def := c.DefaultKeyset()
	named := c.Keyset(KeysetName("acme"))
	byID := c.Keyset(KeysetID{9})
	ct := map[string]any{"name": Sealed(fixtureLeaf), "note": vcvalue.Plain{V: "clear"}}
	record := EncryptedRecord{
		"Age":   {Ciphertext: Sealed(fixtureLeaf), Equality: EqualityTerm{1}, Ore: OreTerm{2}},
		"Email": {Ciphertext: Sealed(fixtureLeaf)},
	}
	rows := []recordRow{{Age: 1, Email: "a@b.c"}}
	var out []recordRow
	var one recordRow
	calls := map[string]func() error{
		"KeysetID by name":   func() error { _, err := named.KeysetID(ctx); return err },
		"KeysetID by id":     func() error { _, err := byID.KeysetID(ctx); return err },
		"KeysetID default":   func() error { _, err := def.KeysetID(ctx); return err },
		"Encrypt":            func() error { _, err := def.Encrypt(ctx, map[string]any{"a": 1}, []byte("aad")); return err },
		"EncryptElement":     func() error { _, err := named.EncryptElement(ctx, "row", nil); return err },
		"Decrypt bound":      func() error { _, err := byID.Decrypt(ctx, ct, nil); return err },
		"Decrypt any":        func() error { _, err := c.Decrypt(ctx, ct, []byte("aad")); return err },
		"DecryptElement any": func() error { _, err := c.DecryptElement(ctx, Sealed(fixtureLeaf), nil); return err },
		"Term equality":      func() error { _, err := def.Term(ctx, uint32(34), MustContext("users/age"), Equality); return err },
		"Term match":         func() error { _, err := named.Term(ctx, "alice", MustContext("users/email"), Match); return err },
		"Term ore extended": func() error {
			c, _ := MustContext("users/age").With(uint64(7))
			_, err := byID.Term(ctx, 1.5, c, Ore)
			return err
		},
		"Term ope bytes":       func() error { _, err := def.Term(ctx, []byte{1}, MustContext("k"), Ope); return err },
		"EncryptRecords":       func() error { _, err := def.EncryptRecords(ctx, rows); return err },
		"EncryptRecords ext":   func() error { _, err := named.EncryptRecords(ctx, &rows, ExtendContext(uint64(7), "eu")); return err },
		"EncryptRecord":        func() error { _, err := byID.EncryptRecord(ctx, rows[0]); return err },
		"DecryptRecords bound": func() error { return def.DecryptRecords(ctx, []EncryptedRecord{record}, &out) },
		"DecryptRecords any":   func() error { return c.DecryptRecords(ctx, []EncryptedRecord{record, record}, &out) },
		"DecryptRecord any":    func() error { return c.DecryptRecord(ctx, record, &one, ExtendContext("x")) },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrState) {
			t.Errorf("%s: %v, want ErrState (every input parsed, no cipher)", name, err)
		}
	}
}

// The inputs the guest must refuse are refused before it looks for a
// cipher: ErrEncoding, not ErrState, on the same uninitialised instance.
func TestGuestRefusesMalformedInputsBeforeState(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	def := c.DefaultKeyset()
	type badRow struct {
		Age float64 `stash:"context=users/age,index=eq"`
	}
	calls := map[string]func() error{
		"float under equality":    func() error { _, err := def.Term(ctx, 1.5, MustContext("k"), Equality); return err },
		"integer under match":     func() error { _, err := def.Term(ctx, 1, MustContext("k"), Match); return err },
		"container as term value": func() error { _, err := def.Term(ctx, []any{1}, MustContext("k"), Ore); return err },
		// NewContext refuses this one now (see
		// TestEmptyContextIsRefusedAtTheRoot); built by hand so the guest's
		// own boundary check stays covered from this side too.
		"empty context part": func() error {
			_, err := def.Term(ctx, 1, Context{node: ""}, Equality)
			return err
		},
		"unknown term kind":      func() error { _, err := def.Term(ctx, 1, MustContext("k"), TermKind(9)); return err },
		"name with spaces":       func() error { _, err := c.Keyset(KeysetName("not a name")).KeysetID(ctx); return err },
		"empty name":             func() error { _, err := c.Keyset(KeysetName("")).KeysetID(ctx); return err },
		"any as a keyset":        func() error { _, err := c.Keyset(anyKeyset{}).KeysetID(ctx); return err },
		"float under eq in plan": func() error { _, err := def.EncryptRecords(ctx, []badRow{{1.5}}); return err },
		"malformed leaf": func() error {
			_, err := c.Decrypt(ctx, Sealed{1, 2, 3}, nil)
			return err
		},
		"record without c": func() error {
			return c.DecryptRecord(ctx, EncryptedRecord{"Age": {Equality: EqualityTerm{1}}, "Email": {Ciphertext: Sealed(fixtureLeaf)}}, new(recordRow))
		},
	}
	for name, call := range calls {
		err := call()
		if errors.Is(err, ErrState) {
			t.Errorf("%s: reached the cipher (ErrState); must be refused at parse", name)
		} else if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClosedClientIsState(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.DefaultKeyset().Encrypt(ctx, "x", nil); !errors.Is(err, ErrState) {
		t.Fatalf("Encrypt after Close: %v", err)
	}
}

func TestHostilePointerLengthPairsAreStatusesNotTraps(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	inst := c.inst
	// A null pointer with a nonzero length must fail closed.
	res, err := inst.cipherInit.Call(ctx, 0, 64)
	if err != nil {
		t.Fatalf("init with null pointer trapped: %v", err)
	}
	if _, cerr := packedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
		t.Fatalf("null pointer: %v, want ErrEncoding", cerr)
	}
	staged, err := inst.allocWrite(ctx, bytes.Repeat([]byte{0x2a}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer inst.free(ctx, staged)
	for _, hostile := range []uint64{0x7FFF_FFF0, 0xFFFF_FFFF} {
		for name, fn := range map[string]func() ([]uint64, error){
			"se_cipher_init": func() ([]uint64, error) { return inst.cipherInit.Call(ctx, uint64(staged.ptr), hostile) },
			"se_keyset":      func() ([]uint64, error) { return inst.keyset.Call(ctx, uint64(staged.ptr), hostile) },
			"se_encrypt": func() ([]uint64, error) {
				return inst.encrypt.Call(ctx, uint64(staged.ptr), hostile, 0, 0, uint64(staged.ptr), 4)
			},
		} {
			res, err := fn()
			if err != nil {
				t.Fatalf("%s with len %#x trapped: %v", name, hostile, err)
			}
			if _, cerr := packedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
				t.Errorf("%s with len %#x: %v, want ErrEncoding", name, hostile, cerr)
			}
		}
	}
	// An unknown or mismatched free is a no-op, not a trap.
	if _, err := inst.dealloc.Call(ctx, uint64(staged.ptr)+1, 1); err != nil {
		t.Fatalf("dealloc of an unknown pointer trapped: %v", err)
	}
	if _, err := inst.dealloc.Call(ctx, uint64(staged.ptr), 1); err != nil {
		t.Fatalf("dealloc with a mismatched length trapped: %v", err)
	}
	// The instance still works.
	if _, err := c.DefaultKeyset().Encrypt(ctx, "alive", nil); !errors.Is(err, ErrState) {
		t.Fatalf("instance poisoned: %v", err)
	}
}

// The client key crosses into guest memory once, in the config buffer,
// which the guest wipes before any request; the Go-side transport copy is
// wiped too. Neither the hex form nor its decoded bytes may remain in
// linear memory after NewClient returns — success or failure.
func TestClientKeyDoesNotRemainInGuestMemory(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	// Keep the instance to scan it: build the client by hand so a failed
	// init does not tear it down first.
	ctx := context.Background()
	encoded, err := encodeConfig(testConfig(stub.URL))
	if err != nil {
		t.Fatal(err)
	}
	tr := &transport{rt: http.DefaultTransport, token: StaticToken("stub-token")}
	inst, err := newInstance(ctx, guestOrSkip(t), tr)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.close(ctx)
	_, err = inst.call(ctx, inst.cipherInit, buf(encoded))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("init: %v", err)
	}
	mem := inst.module.Memory()
	view, ok := mem.Read(0, mem.Size())
	if !ok {
		t.Fatal("cannot read guest memory")
	}
	for name, needle := range map[string][]byte{
		"key hex":   []byte(testClientKey),
		"key bytes": mustHex(testClientKey),
		"bearer":    []byte("stub-token"),
	} {
		if n := bytes.Count(view, needle); n != 0 {
			t.Errorf("%s found %d times in guest memory after init", name, n)
		}
	}
}

func TestTransportSendCounterAndResponseHeaders(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusUnauthorized, "text/plain", "nope")
	tr := &transport{rt: http.DefaultTransport, token: StaticToken("stub-token")}
	ctx := context.Background()
	inst, err := newInstance(ctx, guestOrSkip(t), tr)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.close(ctx)
	encoded, _ := encodeConfig(testConfig(stub.URL))
	if _, err := inst.call(ctx, inst.cipherInit, buf(encoded)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("init: %v", err)
	}
	if n := tr.sends.Load(); n != 1 {
		t.Fatalf("transport sends = %d, want 1", n)
	}
}

func ExampleNewClient() {
	// A client needs ZeroKMS credentials; see live_test.go for the shape of
	// a real round trip.
	_, err := NewClient(context.Background(), Config{
		ClientID:  "6a70bd18-99ac-4650-b104-37eec3a15b09",
		ClientKey: "...",
		Token:     StaticToken("access token"),
	})
	fmt.Println(err != nil)
	// Output: true
}
