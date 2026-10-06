package encrypt

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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
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

// testConfig is the options for a client of the test credentials against
// url. A test appends to it; a later option wins.
func testConfig(url string) []ClientOption {
	return []ClientOption{WithCredentials(testCredentials(staticToken("stub-token"))), withZeroKMSURL(url)}
}

// testCredentials is the test client id and a fresh copy of the test key,
// with token as the token source.
func testCredentials(token tokenSource) Credentials {
	return newTestCredentials(testClientID, NewClientKey([]byte(testClientKey)), token)
}

// testInit is testConfig as se_cipher_init takes it, for tests that drive
// an instance by hand.
func testInit(url string) initConfig {
	return initConfig{clientID: testClientID, clientKey: NewClientKey([]byte(testClientKey)), zerokmsURL: url}
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
	for name := range map[string]bool{"se_alloc": true, "se_dealloc": true, "se_cipher_init": true, "se_shutdown": true, "se_keyset": true, "se_term": true, "se_encrypt_record": true, "se_decrypt_record": true, "se_plan_check": true, "se_targets": true} {
		if _, ok := compiled.ExportedFunctions()[name]; !ok {
			t.Errorf("guest does not export %s", name)
		}
	}
}

func TestNewClientIssuesTheLoadKeysetRequest(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	_, err := NewClient(context.Background(), testConfig(stub.URL)...)
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
			_, err := NewClient(context.Background(), testConfig(stub.URL)...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewClient: %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("connection refused", func(t *testing.T) {
		stub := newStub(t, http.StatusOK, "application/json", "{}")
		url := stub.URL
		stub.Close()
		_, err := NewClient(context.Background(), testConfig(url)...)
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("NewClient: %v, want ErrTransport", err)
		}
	})
	t.Run("no token", func(t *testing.T) {
		stub := newStub(t, http.StatusOK, "application/json", "{}")
		cfg := testConfig(stub.URL)
		vaultDown := errors.New("vault down")
		cfg = append(cfg, WithCredentials(testCredentials(tokenFunc(func(context.Context) (string, error) { return "", vaultDown }))))
		_, err := NewClient(context.Background(), cfg...)
		if err == nil {
			t.Fatal("NewClient succeeded with no token")
		}
		// The guest reports only that token_get failed; the client attaches
		// what the token source said.
		if !errors.Is(err, vaultDown) {
			t.Fatalf("NewClient: %v, want the token source's error", err)
		}
		if len(stub.requests) != 0 {
			t.Fatalf("a request was made without a token: %+v", stub.requests)
		}
	})
}

func TestRoundTripperFailureIsTransport(t *testing.T) {
	guestOrSkip(t)
	cfg := testConfig("http://zerokms.invalid")
	cfg = append(cfg, WithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no route")
	})))
	_, err := NewClient(context.Background(), cfg...)
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
		cfg = append(cfg, WithTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})))
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := NewClient(ctx, cfg...)
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
		if err := c.Close(); err != nil {
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
		if err := c.Close(); err != nil {
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
			cfg = append(cfg, WithTransport(rt))
			_, err := NewClient(context.Background(), cfg...)
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("NewClient: %v, want ErrTransport", err)
			}
		})
	}
}

// A status that would wrap in the guest's i32 — here to 200 — is refused
// as a transport failure.
func TestOutOfRangeStatusIsTransport(t *testing.T) {
	guestOrSkip(t)
	cases := map[string]int{"negative": -200, "two digits": 99}
	if strconv.IntSize == 64 {
		wraps := int64(1<<32 + 200)
		cases["wraps to 200"] = int(wraps)
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig("http://zerokms.invalid")
			cfg = append(cfg, WithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader("{}")),
				}, nil
			})))
			_, err := NewClient(context.Background(), cfg...)
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("NewClient: %v, want ErrTransport", err)
			}
		})
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
	cfg = append(cfg, WithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/json"}},
			ContentLength: -1,
			Body: io.NopCloser(io.MultiReader(
				strings.NewReader(`{"partial":"`),
				&failingReader{err: io.ErrUnexpectedEOF},
			)),
		}, nil
	})))
	if _, err := NewClient(context.Background(), cfg...); !errors.Is(err, ErrTransport) {
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
	cfg = append(cfg, WithTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		go func() {
			<-returned
			b, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			done <- drained{req: r, body: b, err: err}
		}()
		return nil, errors.New("connection reset")
	})))
	_, err := NewClient(context.Background(), cfg...)
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
	wiped := NewClientKey([]byte(testClientKey))
	wiped.Wipe()
	for name, tc := range map[string]struct {
		id    string
		key   *ClientKey
		token tokenSource
		cache int
	}{
		"no token":       {id: testClientID, key: NewClientKey([]byte(testClientKey))},
		"no client id":   {key: NewClientKey([]byte(testClientKey)), token: staticToken("t")},
		"no key":         {id: testClientID, token: staticToken("t")},
		"empty key":      {id: testClientID, key: NewClientKey(nil), token: staticToken("t")},
		"wiped key":      {id: testClientID, key: wiped, token: staticToken("t")},
		"negative cache": {id: testClientID, key: NewClientKey([]byte(testClientKey)), token: staticToken("t"), cache: -1},
	} {
		cfg := []ClientOption{WithCredentials(newTestCredentials(tc.id, tc.key, tc.token)), WithKeysetCacheSize(tc.cache)}
		if _, err := NewClient(ctx, cfg...); err == nil {
			t.Errorf("%s: NewClient succeeded", name)
		}
		// A refused config consumes the key too: the caller is never handed
		// live material back with the error.
		if !tc.key.IsZero() {
			t.Errorf("%s: the key still holds material after NewClient refused the config", name)
		}
	}
	// Malformed values the guest refuses: no request is made.
	guestOrSkip(t)
	for name, option := range map[string]ClientOption{
		"client id not a uuid": WithCredentials(newTestCredentials("acme", NewClientKey([]byte(testClientKey)), staticToken("t"))),
		"key not hex":          WithCredentials(newTestCredentials(testClientID, NewClientKey([]byte("zz")), staticToken("t"))),
		"bad url":              withZeroKMSURL("not a url"),
	} {
		stub := newStub(t, http.StatusOK, "application/json", "{}")
		_, err := NewClient(ctx, append(testConfig(stub.URL), option)...)
		if !errors.Is(err, ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
		}
		if len(stub.requests) != 0 {
			t.Errorf("%s: a request was made for a malformed config", name)
		}
	}
}

// The client key is consumed by NewClient: whatever the outcome, the bytes
// it was built from are zero once NewClient returns, the key reports
// itself empty, and the credentials never print the material under any
// verb.
//
// The outcome exercised here is the guest's init failing (a refused
// token); the refused-config outcomes are in TestConfigValidation, and
// the successful one in the live test, which is the only place a client
// can be built against a real load-keyset response. The wipe precedes the
// init call, so the three paths share it.
func TestClientKeyIsConsumedAndNeverPrinted(t *testing.T) {
	material := []byte(testClientKey)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	key := NewClientKey(material)
	creds := newTestCredentials(testClientID, key, staticToken("stub-token"))
	cfg := append(testConfig(stub.URL), WithCredentials(creds))
	// Resolving consumes the credentials, so the printed resolution is a
	// separate set's, over another copy of the key.
	resolved, err := newTestCredentials(testClientID, NewClientKey([]byte(testClientKey)), staticToken("stub-token")).resolve(context.Background(), resolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.ClientKey.Wipe()
	// %x and %d reach a struct's fields without asking a Stringer; the
	// key's Formatter answers for them.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for what, v := range map[string]any{"Credentials": creds, "ResolvedCredentials": *resolved} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, testClientKey[:16]) || strings.Contains(out, hex.EncodeToString(material[:8])) {
				t.Errorf("%s under %s prints the key: %q", what, verb, out)
			}
		}
	}
	guestOrSkip(t)
	if _, err := NewClient(context.Background(), cfg...); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized", err)
	}
	if !key.IsZero() {
		t.Error("the key still holds material after NewClient")
	}
	for i, b := range material {
		if b != 0 {
			t.Fatalf("byte %d of the key material was not wiped", i)
		}
	}
	// A consumed key does not make a second client, says so, and asks
	// nothing of ZeroKMS trying.
	before := len(stub.requests)
	if _, err := NewClient(context.Background(), cfg...); !errors.Is(err, ErrCredentialsConsumed) {
		t.Errorf("NewClient with a consumed key: %v, want ErrCredentialsConsumed before any request", err)
	}
	if len(stub.requests) != before {
		t.Errorf("a consumed key made %d request(s)", len(stub.requests)-before)
	}
}

// rawInstance is a guest that was never initialised: every well-formed
// operation is ErrState there, every malformed one ErrEncoding.
func rawInstance(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	inst, err := newInstance(ctx, guestOrSkip(t), &transport{rt: http.DefaultTransport, token: staticToken("t")}, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(inst, nil)
	t.Cleanup(func() { _ = c.Close() })
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

// usersPlan is the declaration the record tests send: what a generated
// users package lowers its tags to.
func usersPlan() *record.Plan {
	return &record.Plan{Context: []string{"users"}, Fields: []record.Field{
		{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Equality, record.Ore}},
		{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality, record.Match}},
	}}
}

func usersRow(age uint32, email string) record.Source {
	return record.Source{"age": age, "email": email}
}

// fixtureRecord is a stored record of usersPlan with no real key behind it.
func fixtureRecord() record.Sealed {
	return record.Sealed{
		"age":   {Ciphertext: fixtureLeaf, Terms: map[record.Output][]byte{record.Equality: {1}, record.Ore: {2}}},
		"email": {Ciphertext: fixtureLeaf},
	}
}

// A record opened under a plan that seals a field it does not carry is
// refused on the host, with the field named, before the guest is asked.
// A record whose target field has no EQL value is refused by the host,
// before the guest sees it: the errNoEQL branch, which a change could
// otherwise drop and send a malformed record on.
func TestTargetWithoutEQLIsRefusedBeforeTheGuest(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	plan := &record.Plan{
		Context: []string{"users"},
		Fields:  []record.Field{{Name: "email", Kind: record.String, Target: "TextEq"}},
	}
	for name, rec := range map[string]record.Sealed{
		"no outputs": {"email": {}},
		"a ciphertext where the EQL value should be": {"email": {Ciphertext: fixtureLeaf}},
		"the field missing":                          {},
	} {
		_, err := c.DefaultKeyset().Open(ctx, plan, []record.Sealed{rec})
		if !errors.Is(err, errNoEQL) || errors.Is(err, ErrState) || !strings.Contains(err.Error(), `field "email"`) {
			t.Errorf("%s: Open = %v, want errNoEQL before the guest, naming the field", name, err)
		}
	}
}

// Query refuses a field the plan does not have, and a field that names no
// EQL type, before the guest is asked.
func TestQueryRejectsMissingAndNonTargetFieldsBeforeTheGuest(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	for _, field := range []string{"email", "missing"} {
		_, err := c.DefaultKeyset().Query(ctx, usersPlan(), field, "a@b.c")
		if !errors.Is(err, ErrEncoding) || errors.Is(err, ErrState) || !strings.Contains(err.Error(), field) {
			t.Errorf("Query(%q) = %v, want ErrEncoding before the guest, naming the field", field, err)
		}
	}
}

func TestMismatchedPlanIsRefusedBeforeTheGuest(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	partial := record.Sealed{"age": {Ciphertext: fixtureLeaf}}
	_, err := c.DefaultKeyset().Open(ctx, usersPlan(), []record.Sealed{partial})
	if !errors.Is(err, errNoCiphertext) || errors.Is(err, ErrState) || !strings.Contains(err.Error(), `field "email"`) {
		t.Fatalf("mismatched plan: %v, want the host's refusal naming the field", err)
	}
	// A source row missing a field, or carrying one the plan does not name,
	// is refused the same way.
	for name, row := range map[string]record.Source{
		"missing": {"age": uint32(1)},
		"extra":   {"age": uint32(1), "email": "a@b.c", "stray": "x"},
	} {
		_, err := c.DefaultKeyset().Seal(ctx, usersPlan(), []record.Source{row})
		if !errors.Is(err, ErrEncoding) || errors.Is(err, ErrState) {
			t.Errorf("%s row: %v, want ErrEncoding before the guest", name, err)
		}
	}
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
	tenant := def.Extend(uint64(7), "eu", []byte{1})
	rows := []record.Source{usersRow(1, "a@b.c"), usersRow(2, "b@c.d")}
	records := []record.Sealed{fixtureRecord(), fixtureRecord()}
	calls := map[string]func() error{
		"KeysetID by name": func() error { _, err := named.KeysetID(ctx); return err },
		"KeysetID by id":   func() error { _, err := byID.KeysetID(ctx); return err },
		"KeysetID default": func() error { _, err := def.KeysetID(ctx); return err },
		"Seal default":     func() error { _, err := def.Seal(ctx, usersPlan(), rows); return err },
		"Seal named":       func() error { _, err := named.Seal(ctx, usersPlan(), rows[:1]); return err },
		"Seal extended":    func() error { _, err := tenant.Seal(ctx, usersPlan(), rows); return err },
		"Open bound":       func() error { _, err := byID.Open(ctx, usersPlan(), records); return err },
		"Open extended":    func() error { _, err := tenant.Open(ctx, usersPlan(), records); return err },
		"Open any":         func() error { _, err := c.Open(ctx, usersPlan(), records); return err },
		"Derive equality":  func() error { _, err := def.Derive(ctx, usersPlan(), "age", record.Equality, uint32(34)); return err },
		"Derive match":     func() error { _, err := named.Derive(ctx, usersPlan(), "email", record.Match, "alice"); return err },
		"Derive ore ext":   func() error { _, err := tenant.Derive(ctx, usersPlan(), "age", record.Ore, uint32(1)); return err },
		"Derive ope": func() error {
			p := usersPlan()
			p.Fields[0].Outputs = append(p.Fields[0].Outputs, record.Ope)
			_, err := byID.Derive(ctx, p, "age", record.Ope, uint32(1))
			return err
		},
		"Seal untyped": func() error {
			p := &record.Plan{Context: []string{"documents", "v2"}, Fields: []record.Field{{Name: "value", Outputs: []record.Output{record.Ciphertext}}}}
			_, err := def.Seal(ctx, p, []record.Source{{"value": map[string]any{"title": "x", "tags": []string{"a"}}}})
			return err
		},
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
	plan := usersPlan()
	floatAge := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "age", Kind: record.Float64, Outputs: []record.Output{record.Ciphertext, record.Equality}}}}
	matchInt := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Match}}}}
	calls := map[string]func() error{
		"float under equality":    func() error { _, err := def.Derive(ctx, floatAge, "age", record.Equality, 1.5); return err },
		"integer under match":     func() error { _, err := def.Derive(ctx, matchInt, "age", record.Match, uint32(1)); return err },
		"container as term value": func() error { _, err := def.Derive(ctx, plan, "age", record.Equality, []any{1}); return err },
		"a kind the type refuses": func() error { _, err := def.Seal(ctx, matchInt, []record.Source{usersRow(1, "x")}); return err },
		"a value of another kind": func() error {
			_, err := def.Seal(ctx, plan, []record.Source{{"age": "thirty", "email": "x"}})
			return err
		},
		"a non-leaf under c": func() error {
			_, err := def.Open(ctx, plan, []record.Sealed{{"age": {Ciphertext: []byte{0xff}}, "email": {Ciphertext: fixtureLeaf}}})
			return err
		},
		"a term the field lacks":              func() error { _, err := def.Derive(ctx, plan, "age", record.Match, uint32(1)); return err },
		"a field the plan lacks":              func() error { _, err := def.Derive(ctx, plan, "name", record.Equality, "x"); return err },
		"an empty context segment":            func() error { p := usersPlan(); p.Context = []string{""}; _, err := def.Seal(ctx, p, nil); return err },
		"an extension the codec cannot carry": func() error { _, err := def.Extend(1.5).Seal(ctx, plan, nil); return err },
		"a nil keyset selector":               func() error { _, err := c.Keyset(nil).Seal(ctx, plan, nil); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
		}
	}
}

// An indexed field with no declared kind is refused by the Checker, naming
// the field: the engine derives every term from one declared kind, and the
// generator never emits such a declaration, so only a plan built by hand
// reaches this. A sealed-only untyped field passes.
func TestCheckerRefusesAnIndexedUntypedField(t *testing.T) {
	ctx := context.Background()
	checker, err := NewChecker(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer checker.Close()
	for name, outputs := range map[string][]record.Output{
		"equality": {record.Ciphertext, record.Equality},
		"match":    {record.Ciphertext, record.Match},
		"ore":      {record.Ciphertext, record.Ore},
		"ope":      {record.Ope},
	} {
		p := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "age", Kind: record.Untyped, Outputs: outputs}}}
		// Through Check, the Go rule refuses first and names the field.
		err := checker.Check(ctx, p)
		if !errors.Is(err, ErrEncoding) || !strings.Contains(err.Error(), `field "age"`) {
			t.Errorf("%s: err = %v, want ErrEncoding naming the field", name, err)
		}
		// Past it, the engine refuses the same plan (Error::UntypedIndex in
		// stack-encrypt) and the guest reports it as the caller's input. The
		// ABI carries a status word and no message, so the field's name is
		// the Go rule's to give; this asserts the two rules agree.
		encoded, err := vcffi.Marshal(p.Wire())
		if err != nil {
			t.Fatal(err)
		}
		_, err = checker.c.call(ctx, func(inst *instance) ([]byte, error) {
			return inst.call(ctx, inst.planCheck, buf(encoded))
		})
		if !errors.Is(err, ErrEncoding) {
			t.Errorf("%s past Validate: err = %v, want ErrEncoding from the engine", name, err)
		}
	}
	sealed := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "notes", Kind: record.Untyped, Outputs: []record.Output{record.Ciphertext}}}}
	if err := checker.Check(ctx, sealed); err != nil {
		t.Errorf("a sealed-only untyped field: %v", err)
	}
}

// se_plan_check answers with no cipher: a plan the engine runs passes, a
// plan it refuses is ErrEncoding, never ErrState.
func TestPlanCheckAnswersWithoutACipher(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	k := &Checker{c: c}
	if err := k.Check(ctx, usersPlan()); err != nil {
		t.Fatalf("a good plan: %v", err)
	}
	refused := []*record.Plan{
		{Context: []string{"users"}, Fields: []record.Field{{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Match}}}},
		{Context: []string{"users"}, Fields: []record.Field{{Name: "age", Kind: record.Float64, Outputs: []record.Output{record.Equality}}}},
	}
	for i, p := range refused {
		if err := k.Check(ctx, p); !errors.Is(err, ErrEncoding) {
			t.Errorf("plan %d: %v, want ErrEncoding", i, err)
		}
	}
	// The test binary links encrypt/eql (through the generated test types),
	// so the embedded guest is the build with the EQL types: it lists the
	// catalog and runs a plan that names TextEq. The build without them is
	// asked the same questions in eql_test.go.
	targets, err := k.Targets(ctx)
	if err != nil || len(targets) == 0 {
		t.Fatalf("Targets = %v, %v; want the catalog in the eql build", targets, err)
	}
	found := false
	for _, target := range targets {
		found = found || target.Name == "TextEq"
	}
	if !found {
		t.Fatalf("TextEq is not among the targets: %v", targets)
	}
	textEq := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "email", Kind: record.String, Target: "TextEq"}}}
	if err := k.Check(ctx, textEq); err != nil {
		t.Fatalf("a TextEq field: %v", err)
	}
}

func TestClosedClientIsState(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.DefaultKeyset().Seal(ctx, usersPlan(), []record.Source{usersRow(1, "x")}); !errors.Is(err, ErrState) {
		t.Fatalf("Seal after Close: %v", err)
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
	if _, _, cerr := guest.PackedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
		t.Fatalf("null pointer: %v, want ErrEncoding", cerr)
	}
	staged, err := inst.exports.AllocWrite(ctx, inst.module, bytes.Repeat([]byte{0x2a}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer inst.exports.Free(ctx, staged)
	for _, hostile := range []uint64{0x7FFF_FFF0, 0xFFFF_FFFF} {
		for name, fn := range map[string]func() ([]uint64, error){
			"se_cipher_init": func() ([]uint64, error) { return inst.cipherInit.Call(ctx, uint64(staged.Ptr), hostile) },
			"se_keyset":      func() ([]uint64, error) { return inst.keyset.Call(ctx, uint64(staged.Ptr), hostile) },
			"se_plan_check":  func() ([]uint64, error) { return inst.planCheck.Call(ctx, uint64(staged.Ptr), hostile) },
			"se_encrypt_record": func() ([]uint64, error) {
				return inst.encryptRecord.Call(ctx, uint64(staged.Ptr), hostile, uint64(staged.Ptr), 4, uint64(staged.Ptr), 4)
			},
		} {
			res, err := fn()
			if err != nil {
				t.Fatalf("%s with len %#x trapped: %v", name, hostile, err)
			}
			if _, _, cerr := guest.PackedResult(res[0]); !errors.Is(cerr, ErrEncoding) {
				t.Errorf("%s with len %#x: %v, want ErrEncoding", name, hostile, cerr)
			}
		}
	}
	// An unknown or mismatched free is a no-op, not a trap.
	if _, err := inst.exports.Dealloc.Call(ctx, uint64(staged.Ptr)+1, 1); err != nil {
		t.Fatalf("dealloc of an unknown pointer trapped: %v", err)
	}
	if _, err := inst.exports.Dealloc.Call(ctx, uint64(staged.Ptr), 1); err != nil {
		t.Fatalf("dealloc with a mismatched length trapped: %v", err)
	}
	// The instance still works.
	if _, err := c.DefaultKeyset().Seal(ctx, usersPlan(), []record.Source{usersRow(1, "alive")}); !errors.Is(err, ErrState) {
		t.Fatalf("instance poisoned: %v", err)
	}
}

// The client key crosses into guest memory once, in the config buffer,
// which the guest wipes before any request; the Go-side transport copy is
// wiped too. Neither the hex form nor its decoded bytes may remain in
// linear memory after NewClient returns — success or failure.
func TestClientKeyDoesNotRemainInGuestMemory(t *testing.T) {
	guestOrSkip(t)
	// A body long enough that a hit is not a coincidence of four bytes.
	const errorBody = "refused-4111-9f8e7d6c5b4a-residency-probe"
	stub := newStub(t, http.StatusUnauthorized, "", errorBody)
	// Keep the instance to scan it: build the client by hand so a failed
	// init does not tear it down first.
	ctx := context.Background()
	encoded, err := encodeConfig(testInit(stub.URL))
	if err != nil {
		t.Fatal(err)
	}
	tr := &transport{rt: http.DefaultTransport, token: staticToken("stub-token")}
	inst, err := newInstance(ctx, guestOrSkip(t), tr, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inst.release() }()
	_, err = inst.call(ctx, inst.cipherInit, buf(encoded))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("init: %v", err)
	}
	mem := inst.module.Memory()
	view, ok := mem.Read(0, mem.Size())
	if !ok {
		t.Fatal("cannot read guest memory")
	}
	// The response body is what ZeroKMS answered, placed in guest memory
	// by the transport and wiped by the guest's registry when the call
	// returns; the bearer token and the response headers travel the same
	// way. Nothing a call staged may outlive it.
	for name, needle := range map[string][]byte{
		"key hex":       []byte(testClientKey),
		"key bytes":     mustHex(testClientKey),
		"bearer":        []byte("stub-token"),
		"response body": []byte(errorBody),
	} {
		if n := bytes.Count(view, needle); n != 0 {
			t.Errorf("%s found %d times in guest memory after init", name, n)
		}
	}
}

func TestTransportSendCounterAndResponseHeaders(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusUnauthorized, "text/plain", "nope")
	tr := &transport{rt: http.DefaultTransport, token: staticToken("stub-token")}
	ctx := context.Background()
	inst, err := newInstance(ctx, guestOrSkip(t), tr, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inst.release() }()
	encoded, _ := encodeConfig(testInit(stub.URL))
	if _, err := inst.call(ctx, inst.cipherInit, buf(encoded)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("init: %v", err)
	}
	if n := tr.sends.Load(); n != 1 {
		t.Fatalf("transport sends = %d, want 1", n)
	}
}

func ExampleNewClient() {
	// With no options, NewClient uses AutoCredentials. To supply the
	// credentials yourself, the token comes from an auth strategy —
	// here an access key; live_test.go has a real round trip. The caller
	// opened the store and the strategy, and closes them after the client.
	ctx := context.Background()
	err := func() error {
		store, err := auth.OpenWithoutProfile(ctx)
		if err != nil {
			return err
		}
		defer store.Close()
		strategy, err := store.AccessKey(ctx, "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY", "CSAK...")
		if err != nil {
			return err
		}
		defer strategy.Close()
		client, err := NewClient(ctx, WithCredentials(NewCredentials(
			"6a70bd18-99ac-4650-b104-37eec3a15b09",
			NewClientKey([]byte("...")), // not a real key: NewClient refuses it
			strategy,
		)))
		if err != nil {
			return err
		}
		return client.Close()
	}()
	fmt.Println(err != nil)
	// Output: true
}
