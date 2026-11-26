package encrypt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// These tests are for client keys that are wrong (issue #1850). Each key here
// is made from testClientKey, which is a made-up key. None is a real key.

// testKeyWithBadPermutation is testClientKey with one character changed. The
// change gives the keyset's p3 permutation a repeated entry. The key is still
// valid hex and valid CBOR. Before the fix, deriving the first key from it
// looped forever in the guest, after the load-keyset round trip.
var testKeyWithBadPermutation = strings.Replace(testClientKey, "982102", "982100", 1)

// keysetKMS answers load-keyset as ZeroKMS would, with key material of the
// right length, so a client gets as far as deriving its index key. It counts
// the requests it is sent.
type keysetKMS struct{ sent atomic.Int32 }

func (k *keysetKMS) RoundTrip(r *http.Request) (*http.Response, error) {
	k.sent.Add(1)
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	if !strings.HasSuffix(r.URL.Path, "load-keyset") {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	const id = "3f8a7c1e-6b2d-4e59-9a14-2c7d5e0f8b31"
	material := make([]byte, 0, 17*sha256.Size)
	for j := range 17 {
		sum := sha256.Sum256([]byte{byte(j)})
		material = append(material, sum[:]...)
	}
	body, err := json.Marshal(map[string]any{
		"partial_index_key": map[string]any{"key_material": base64.StdEncoding.EncodeToString(material[:528])},
		"dataset":           map[string]any{"id": id, "name": "default", "description": "", "is_disabled": false, "is_default": true},
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

// newClientWithin runs NewClient and fails the test if it has not returned
// within limit. The call runs on its own goroutine, so a NewClient that never
// returns fails the test, and the test does not wait for it. A guest call
// that never returns can still stop the whole process at the next garbage
// collection, because the collector waits for it. go test's -timeout bounds
// the run in that case.
func newClientWithin(t *testing.T, ctx context.Context, limit time.Duration, opts ...ClientOption) (*Client, error) {
	t.Helper()
	type result struct {
		c   *Client
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := NewClient(ctx, opts...)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.c != nil {
			t.Cleanup(func() { _ = r.c.Close() })
		}
		return r.c, r.err
	case <-time.After(limit):
		t.Fatalf("NewClient did not return within %s", limit)
		return nil, nil
	}
}

// wantClientKeyError fails the test unless err is a malformed client key:
// ErrConfig and ErrEncoding, with a Diagnostic whose Help names
// CS_CLIENT_KEY, and with none of key in its text.
func wantClientKeyError(t *testing.T, err error, key string) {
	t.Helper()
	if !errors.Is(err, ErrConfig) || !errors.Is(err, ErrEncoding) {
		t.Fatalf("error = %v, want ErrConfig and ErrEncoding", err)
	}
	if errors.Is(err, auth.ErrConfig) {
		t.Errorf("error matches auth.ErrConfig, which is a different value: %v", err)
	}
	var d *Diagnostic
	if !errors.As(err, &d) || d.Code != codeClientKey || !strings.Contains(d.Help, envClientKey) {
		t.Errorf("Diagnostic = %+v, want code %s and a Help that names %s", d, codeClientKey, envClientKey)
	}
	// The first and last 16 characters of a long key, or a short key whole.
	leaks := []string{key}
	if len(key) > 16 {
		leaks = []string{key[:16], key[len(key)-16:]}
	}
	for _, leak := range leaks {
		if strings.Contains(err.Error(), leak) || (d != nil && (strings.Contains(d.Message, leak) || strings.Contains(d.Help, leak))) {
			t.Errorf("the error carries key material: %q", err)
		}
	}
}

// A key with one wrong character fails NewClient with ErrConfig, before
// ZeroKMS is asked for anything. Before the fix, this key passed the guest's
// config parse, and deriving the index key from the load-keyset response
// looped forever.
//
// The limits are long because one NewClient can take about 20 seconds
// under the race detector, most of it loading the guest. Without the race
// detector it takes about 2 seconds. The watchdog only has to tell a
// NewClient that returns from one that never does.
func TestNewClientRefusesAKeyWithABadPermutation(t *testing.T) {
	guestOrSkip(t)
	kms := &keysetKMS{}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := time.Now()
	_, err := newClientWithin(t, ctx, 120*time.Second,
		WithCredentials(newTestCredentials(testClientID, NewClientKey([]byte(testKeyWithBadPermutation)), staticToken("t"))),
		withZeroKMSURL("http://zerokms.invalid"), WithTransport(kms))
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("NewClient ran to its deadline (%s): %v", time.Since(start), err)
	}
	wantClientKeyError(t, err, testKeyWithBadPermutation)
	if n := kms.sent.Load(); n != 0 {
		t.Errorf("ZeroKMS was asked %d times for a key that is not valid", n)
	}
}

// The same client, with the key unchanged, is built: the fake ZeroKMS is
// enough to get past the step where the bad key looped.
func TestNewClientAcceptsTheKeyTheBadOneWasMadeFrom(t *testing.T) {
	guestOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, err := newClientWithin(t, ctx, 120*time.Second,
		WithCredentials(newTestCredentials(testClientID, NewClientKey([]byte(testClientKey)), staticToken("t"))),
		withZeroKMSURL("http://zerokms.invalid"), WithTransport(&keysetKMS{}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
}

// Keys that are not hex or padded base64 can never decode. NewClient refuses
// them on the host, before it loads the crypto guest, and the error names
// where the key came from. "not wasm" as the guest proves the guest is never
// loaded.
func TestNewClientRefusesAKeyThatIsNotHexOrBase64(t *testing.T) {
	// If the check were missing, AccessKeyCredentials would exchange the
	// access key. Point that at a port nothing listens on.
	t.Setenv("CS_CTS_HOST", "http://127.0.0.1:1")
	for name, bad := range map[string]string{
		"a character in neither alphabet": testClientKey[:len(testClientKey)-1] + "!",
		"a trailing newline":              testClientKey + "\n",
		"padding in the middle":           "AAAA=AAA",
		"hex of odd length":               testClientKey[:len(testClientKey)-1],
	} {
		t.Run(name, func(t *testing.T) {
			for source, creds := range map[string]Credentials{
				"NewCredentials": newTestCredentials(testClientID, NewClientKey([]byte(bad)), staticToken("t")),
				"AccessKeyCredentials": AccessKeyCredentials{
					ClientID: testClientID, ClientKey: Secret(bad), ClientAccessKey: testAccessKey, WorkspaceCRN: testCRN,
				},
			} {
				_, err := NewClient(context.Background(), WithCredentials(creds), withGuest([]byte("not wasm")), withZeroKMSURL("http://zerokms.invalid"))
				wantClientKeyError(t, err, bad)
				if !strings.Contains(err.Error(), "hex or padded base64") {
					t.Errorf("%s: the error does not say what a key must be: %q", source, err)
				}
				if source == "AccessKeyCredentials" && !strings.Contains(err.Error(), "ClientKey (CS_CLIENT_KEY)") {
					t.Errorf("%s: the error does not name the field: %q", source, err)
				}
			}
		})
	}
}

// AutoCredentials names CS_CLIENT_KEY when the variable holds a key that is
// not hex or padded base64.
func TestAutoCredentialsRefusesAKeyVariableThatIsNotHexOrBase64(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	t.Setenv(envClientID, testClientID)
	t.Setenv(envClientKey, testClientKey[:len(testClientKey)-1]+"!")
	_, err := resolve(t)
	wantClientKeyError(t, err, testClientKey)
	if !strings.Contains(err.Error(), envClientKey) {
		t.Fatalf("resolve: %v, want an error naming %s", err, envClientKey)
	}
}

// The encoding check accepts every form the guest decodes, and refuses the
// rest.
func TestValidKeyEncoding(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want bool
	}{
		{"lower-case hex", testClientKey, true},
		{"upper-case hex", strings.ToUpper(testClientKey), true},
		{"padded base64", base64.StdEncoding.EncodeToString(mustHex(testClientKey)), true},
		{"base64 with no padding needed", "AAECAwQF", true},
		{"base64 with one pad", "AAECAwQ=", true},
		{"base64 with two pads", "AAECAw==", true},
		{"empty", "", false},
		{"hex of odd length", "abc", false},
		{"unpadded base64", "AAECAw", false},
		{"three pads", "AA===", false},
		{"padding in the middle", "AA=AAAAA", false},
		{"URL-safe base64", "AAEC-_8=", false},
		{"a space", "AAEC AwQ=", false},
		{"a trailing newline", testClientKey + "\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := validKeyEncoding(tt.in); got != tt.want {
				t.Errorf("validKeyEncoding = %v, want %v", got, tt.want)
			}
		})
	}
}
