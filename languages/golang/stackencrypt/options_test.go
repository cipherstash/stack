package stackencrypt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackauth"
)

// Every option sets its one field, and a later option setting the same
// field wins. The zero value of each is the default NewClient applies.
func TestClientOptionsSetTheirField(t *testing.T) {
	creds := AutoCredentials()
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	wasm := []byte("\x00asm")
	var got clientOptions
	for _, opt := range []ClientOption{
		WithZeroKMSURL("https://first.example"),
		WithCredentials(creds),
		WithZeroKMSURL("https://second.example"),
		WithKeysetCacheSize(4096),
		WithTransport(rt),
		WithGuest(wasm),
		WithRequireLockedMemory(),
	} {
		opt(&got)
	}
	if got.credentials != creds || got.zerokmsURL != "https://second.example" || got.keysetCacheSize != 4096 ||
		got.transport == nil || string(got.guest) != string(wasm) || !got.requireLockedMemory {
		t.Fatalf("options = %+v", got)
	}
}

// The endpoint a later WithZeroKMSURL names is the one NewClient uses.
func TestLaterZeroKMSURLWins(t *testing.T) {
	guestOrSkip(t)
	first := newStub(t, http.StatusUnauthorized, "", "first")
	second := newStub(t, http.StatusUnauthorized, "", "second")
	_, err := NewClient(context.Background(),
		WithCredentials(testCredentials(staticToken("stub-token"))),
		WithZeroKMSURL(first.URL),
		WithZeroKMSURL(second.URL),
	)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v", err)
	}
	if len(first.requests) != 0 || len(second.requests) != 1 {
		t.Fatalf("requests: first %d, second %d; want only the second", len(first.requests), len(second.requests))
	}
}

// A later WithKeysetCacheSize replaces an earlier one before anything is
// checked: a negative size overridden by zero, the default, is accepted,
// and the client goes on to ZeroKMS.
func TestLaterKeysetCacheSizeWins(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	_, err := NewClient(context.Background(),
		WithCredentials(testCredentials(staticToken("stub-token"))),
		WithZeroKMSURL(stub.URL),
		WithKeysetCacheSize(-1),
		WithKeysetCacheSize(0),
	)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized from the stub", err)
	}
	if len(stub.requests) != 1 {
		t.Fatalf("requests: %d, want one: the overridden size was refused", len(stub.requests))
	}
}

// countingTransport records the hosts a RoundTripper was asked to reach.
type countingTransport struct {
	mu    sync.Mutex
	hosts map[string]int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	if c.hosts == nil {
		c.hosts = map[string]int{}
	}
	c.hosts[r.URL.Host]++
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func (c *countingTransport) count(rawURL string) int {
	u, _ := url.Parse(rawURL)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hosts[u.Host]
}

// OIDCFederation mints its token from the provider's through CTS, asking
// the provider only when a token has to be minted; its client key comes
// from the environment as AutoCredentials' does; and WithTransport carries
// the token exchange as well as the ZeroKMS request.
func TestOIDCFederationThroughTheClientTransport(t *testing.T) {
	guestOrSkip(t)
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	auth := newAuthServer(t)
	t.Setenv(envClientID, testClientID)
	t.Setenv(envClientKey, testClientKey)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	var idpCalls atomic.Int32
	provider := stackauth.OIDCProviderFunc(func(context.Context) (string, error) {
		idpCalls.Add(1)
		return "idp-token", nil
	})
	rt := &countingTransport{}
	_, err := NewClient(context.Background(),
		WithCredentials(OIDCFederation(testCRN, provider)),
		WithZeroKMSURL(stub.URL),
		WithTransport(rt),
	)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized from the stub", err)
	}
	if idpCalls.Load() != 1 || auth.calls.Load() != 1 {
		t.Fatalf("provider calls %d, exchanges %d; want one of each", idpCalls.Load(), auth.calls.Load())
	}
	if len(stub.requests) != 1 || stub.requests[0].auth != "Bearer "+auth.jwt {
		t.Fatalf("ZeroKMS requests = %+v, want one bearing the federated token", stub.requests)
	}
	if rt.count(auth.URL) != 1 || rt.count(stub.URL) != 1 {
		t.Fatalf("transport saw %v, want the exchange and the ZeroKMS request", rt.hosts)
	}
}

func TestOIDCFederationResolvesTheKeyLikeAuto(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	provider := stackauth.OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil })
	resolved, err := OIDCFederation(testCRN, provider).resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Close()
	if resolved.ClientID != profileClientID || guest.KeyBytes(resolved.ClientKey) == nil {
		t.Errorf("ClientID = %q, want the profile's", resolved.ClientID)
	}
	// No CRN is a configuration error from the strategy, before any
	// provider or key is asked.
	if _, err := OIDCFederation("", provider).resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport}); !errors.Is(err, stackauth.ErrAuthConfig) {
		t.Fatalf("OIDCFederation with no CRN: %v, want ErrAuthConfig", err)
	}
}

// OIDCFederation's strategy options reach the strategy: WithAuthBaseURL
// pins CTS for these credentials, over CS_CTS_HOST, which here names a
// decoy that fails the test if it is asked.
func TestOIDCFederationTakesStrategyOptions(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	auth := newAuthServer(t)
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("CS_CTS_HOST was asked (%s) though WithAuthBaseURL pinned CTS", r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(decoy.Close)
	t.Setenv("CS_CTS_HOST", decoy.URL)
	t.Setenv(envClientID, testClientID)
	t.Setenv(envClientKey, testClientKey)
	provider := stackauth.OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil })
	creds := OIDCFederation(testCRN, provider, stackauth.WithAuthBaseURL(auth.URL))
	resolved, err := creds.resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Close()
	resolved.ClientKey.Wipe()
	if got := token(t, resolved); got != auth.jwt {
		t.Fatalf("token = %q, want the pinned CTS's", got)
	}
	if auth.calls.Load() != 1 {
		t.Fatalf("exchanges at the pinned CTS: %d, want one", auth.calls.Load())
	}
}
