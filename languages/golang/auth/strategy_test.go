package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

const testCRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"

func testJWT(t *testing.T, issuer string) string {
	t.Helper()
	return testJWTFor(t, issuer, "CS|test")
}

// testJWTFor is testJWT with a chosen subject, so a test with several
// callers can tell whose token came back.
func testJWTFor(t *testing.T, issuer, sub string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "sub": sub, "workspace": "ZVATKW3VHMFG27DY",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// jwtSubject reads the sub claim of an unverified JWT.
func jwtSubject(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Sub
}

func TestAccessKeyStrategyCachesAndPreservesRequest(t *testing.T) {
	guestOrSkip(t)
	var calls atomic.Int32
	var jwt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/authorise" {
			t.Errorf("request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if want := (map[string]any{"accessKey": "CSAKtestKeyId.testKeySecret"}); !reflect.DeepEqual(body, want) {
			t.Errorf("request body = %#v, want %#v", body, want)
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	jwt = testJWT(t, server.URL)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	for i := 0; i < 2; i++ {
		got, err := strategy.Token(context.Background())
		if err != nil || got != jwt {
			t.Fatalf("Token #%d = %q, %v", i, got, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("auth requests = %d, want 1 cached exchange", calls.Load())
	}
}

// The provider is asked on every Token call, and each distinct IdP token is
// exchanged once: two users through one strategy each get the CTS token
// minted for their own IdP token, and a user whose token is cached is not
// exchanged again. One cached token per strategy handed the second user the
// first user's token (stack-auth CIP-4301).
// callerKey carries the caller's identity in the ctx of a Token call, the
// way a request-scoped provider finds its user.
type callerKey struct{}

func TestOIDCStrategyFederatesEachProviderTokenOnce(t *testing.T) {
	guestOrSkip(t)
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		var body struct {
			OIDCToken   string `json:"oidcToken"`
			WorkspaceID string `json:"workspaceId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.WorkspaceID != "ZVATKW3VHMFG27DY" {
			t.Errorf("workspaceId = %q, want ZVATKW3VHMFG27DY", body.WorkspaceID)
		}
		if ua := r.Header.Get("User-Agent"); !isStackAuthGoAgent(ua) {
			t.Errorf("OIDC federation User-Agent = %q, want stack-auth/<version> (Go)", ua)
		}
		// The CTS token names the IdP token it was exchanged from, so the
		// test can tell whose token the strategy handed back.
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWTFor(t, "https://cts.example", "CS|"+body.OIDCToken), time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	var providerCalls atomic.Int32
	// The provider learns who is calling only from the ctx of the Token
	// call, as a provider reading the request's user does; a shared variable
	// would pass even if the guest handed it some other context.
	strategy, err := profile.OIDC(context.Background(), testCRN, OIDCProviderFunc(func(ctx context.Context) (string, error) {
		providerCalls.Add(1)
		idp, ok := ctx.Value(callerKey{}).(string)
		if !ok {
			return "", errors.New("provider did not receive the Token caller's context")
		}
		return idp, nil
	}), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	tokenFor := func(idp string) string {
		token, err := strategy.Token(context.WithValue(context.Background(), callerKey{}, idp))
		if err != nil {
			t.Fatalf("Token for %s: %v", idp, err)
		}
		return token
	}
	a := tokenFor("idp-a")
	b := tokenFor("idp-b")
	again := tokenFor("idp-a")
	if got := jwtSubject(t, a); got != "CS|idp-a" {
		t.Errorf("A's token subject = %q, want CS|idp-a", got)
	}
	if got := jwtSubject(t, b); got != "CS|idp-b" {
		t.Errorf("B's token subject = %q, want CS|idp-b: B was handed A's token", got)
	}
	if again != a {
		t.Errorf("A's second call did not serve A's cached token")
	}
	if exchanges.Load() != 2 {
		t.Errorf("exchanges = %d, want 2 (one per IdP token)", exchanges.Load())
	}
	if providerCalls.Load() != 3 {
		t.Errorf("provider calls = %d, want 3 (one per Token call)", providerCalls.Load())
	}
}

// WithCacheCapacity reaches the Rust builder: with room for no JWT at all,
// the same IdP token is exchanged on every Token call, where the default
// (1024) serves the second call from the cache, as the test above shows.
func TestOIDCStrategyCacheCapacityZeroExchangesEveryCall(t *testing.T) {
	guestOrSkip(t)
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		var body struct {
			OIDCToken string `json:"oidcToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWTFor(t, "https://cts.example", "CS|"+body.OIDCToken), time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.OIDC(context.Background(), testCRN, OIDCProviderFunc(func(context.Context) (string, error) {
		return "idp-a", nil
	}), WithBaseURL(server.URL), WithCacheCapacity(0))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	for i := 0; i < 2; i++ {
		token, err := strategy.Token(context.Background())
		if err != nil {
			t.Fatalf("Token #%d: %v", i, err)
		}
		if got := jwtSubject(t, token); got != "CS|idp-a" {
			t.Errorf("Token #%d subject = %q, want CS|idp-a", i, got)
		}
	}
	if exchanges.Load() != 2 {
		t.Errorf("exchanges = %d, want 2 (nothing cached)", exchanges.Load())
	}
}

func TestUsageLimitIsPreservedAcrossGuest(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		fmt.Fprint(w, `{"cs_code":"USAGE_LIMIT_EXCEEDED"}`)
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrUsageLimit) {
		t.Fatalf("Token error = %v, want %v", err, ErrUsageLimit)
	}
	wantCode(t, err, "stack_auth::usage_limit_exceeded")
}

func TestDeviceRefreshReportsInvalidClient(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
	}))
	defer server.Close()
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Token error = %v, want %v", err, ErrInvalidClient)
	}
	wantCode(t, err, "stack_auth::invalid_client")
}

// Match stack-auth's AutoStrategy order: an access key wins over a stored
// device session; with no key, the current workspace's auth.json is used.
func TestAutoPrefersAccessKeyThenDeviceSession(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	var accessCalls, refreshCalls atomic.Int32
	var accessJWT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/authorise":
			accessCalls.Add(1)
			fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, accessJWT, time.Now().Add(time.Hour).Unix())
		case "/oauth/token":
			refreshCalls.Add(1)
			fmt.Fprint(w, `{"access_token":"device-token","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
		default:
			t.Errorf("unexpected auth path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	accessJWT = testJWT(t, server.URL)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	if err := profile.SetCurrentWorkspace(context.Background(), wsA); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CS_CLIENT_ACCESS_KEY", "CSAKtestKeyId.testKeySecret")
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	strategy, err := profile.Auto(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	token, err := strategy.Token(context.Background())
	if err != nil || token != accessJWT {
		t.Fatalf("access key: token %q, error %v", token, err)
	}
	strategy.Close()
	if accessCalls.Load() != 1 || refreshCalls.Load() != 0 {
		t.Fatalf("access key should win: access=%d refresh=%d", accessCalls.Load(), refreshCalls.Load())
	}
	if err := os.Unsetenv("CS_CLIENT_ACCESS_KEY"); err != nil {
		t.Fatal(err)
	}
	strategy, err = profile.Auto(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	token, err = strategy.Token(context.Background())
	if err != nil || token != "device-token" {
		t.Fatalf("device fallback: token %q, error %v", token, err)
	}
	if refreshCalls.Load() != 1 {
		t.Fatalf("device refresh requests = %d, want 1", refreshCalls.Load())
	}
	if err := profile.ClearCurrentWorkspace(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Auto(context.Background(), WithBaseURL(server.URL)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("no credentials: error = %v, want %v", err, ErrNotAuthenticated)
	}
}

func expiredDeviceProfile(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	workspaceDir := filepath.Join(dir, "workspaces", wsA)
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf(`{"access_token":"old","refresh_token":"refresh-1","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2.aws","client_id":"client-1"}`, time.Now().Add(-time.Hour).Unix())
	write(t, filepath.Join(workspaceDir, "auth.json"), data)
	return dir, workspaceDir
}

func TestDeviceSessionFreshTokenDoesNotTakeRefreshLock(t *testing.T) {
	guestOrSkip(t)
	dir, workspaceDir := expiredDeviceProfile(t)
	write(t, filepath.Join(workspaceDir, "auth.json"), fmt.Sprintf(`{"access_token":"fresh","refresh_token":"refresh-1","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2.aws","client_id":"client-1"}`, time.Now().Add(time.Hour).Unix()))
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	workspace, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := workspace.DeviceSession(context.Background(), WithBaseURL("https://cts.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	path, err := workspace.LockPath(context.Background(), "auth.json")
	if err != nil {
		t.Fatal(err)
	}
	err = withRefreshLock(context.Background(), path, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		token, err := strategy.Token(ctx)
		if err != nil || token != "fresh" {
			return fmt.Errorf("fresh token while lock is held = %q, %v", token, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeviceSessionMissingAndInvalidProfilesKeepTheirErrors(t *testing.T) {
	guestOrSkip(t)
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"missing", "", ErrNotFound},
		{"invalid JSON", "{", ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			workspaceDir := filepath.Join(dir, "workspaces", wsA)
			if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.body != "" {
				write(t, filepath.Join(workspaceDir, "auth.json"), tc.body)
			}
			profile, err := Open(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Close()
			workspace, err := profile.WorkspaceStore(context.Background(), wsA)
			if err != nil {
				t.Fatal(err)
			}
			strategy, err := workspace.DeviceSession(context.Background(), WithBaseURL("https://cts.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			defer strategy.Close()
			if _, err := strategy.Token(context.Background()); !errors.Is(err, tc.want) {
				t.Fatalf("Token error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAutoUsesEnvironmentPresenceAndProfileExistence(t *testing.T) {
	guestOrSkip(t)
	dir, workspaceDir := expiredDeviceProfile(t)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	if err := profile.SetCurrentWorkspace(context.Background(), wsA); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	t.Setenv("CS_CLIENT_ACCESS_KEY", "")
	if _, err := profile.Auto(context.Background()); !errors.Is(err, ErrConfig) {
		t.Fatalf("set but empty access key: error = %v, want %v", err, ErrConfig)
	}
	// A key that does not parse is a configuration error like the empty one,
	// the class Rust's AutoStrategy reports, not a malformed-input error. It
	// is the one guest call that receives an access key and fails before
	// any request, and its error never quotes the key.
	const keyMarker = "leak-marker-access-key"
	t.Setenv("CS_CLIENT_ACCESS_KEY", keyMarker)
	if _, err := profile.Auto(context.Background()); !errors.Is(err, ErrConfig) {
		t.Fatalf("malformed access key: error = %v, want %v", err, ErrConfig)
	} else if d := wantDiagnostic(t, err, "stack_auth::invalid_access_key"); strings.Contains(fmt.Sprintf("%v %+v", err, *d), keyMarker) {
		t.Fatalf("the access key is in the Diagnostic: %v %+v", err, *d)
	}
	if _, err := profile.AccessKey(context.Background(), "invalid", "CSAKtestKeyId.testKeySecret"); !errors.Is(err, ErrConfig) {
		t.Fatalf("malformed CRN for access key: error = %v, want %v", err, ErrConfig)
	} else {
		wantCode(t, err, "stack_auth::invalid_crn")
	}
	provider := OIDCProviderFunc(func(context.Context) (string, error) { return "", nil })
	if _, err := profile.OIDC(context.Background(), "invalid", provider); !errors.Is(err, ErrConfig) {
		t.Fatalf("malformed CRN for OIDC: error = %v, want %v", err, ErrConfig)
	}
	if err := os.Unsetenv("CS_CLIENT_ACCESS_KEY"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CS_WORKSPACE_CRN", "invalid")
	if _, err := profile.Auto(context.Background()); !errors.Is(err, ErrConfig) {
		t.Fatalf("invalid CRN without key: error = %v, want %v", err, ErrConfig)
	}
	if err := os.Unsetenv("CS_WORKSPACE_CRN"); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(workspaceDir, "auth.json"), "{")
	strategy, err := profile.Auto(context.Background())
	if err != nil {
		t.Fatalf("existing but invalid profile must select device strategy: %v", err)
	}
	defer strategy.Close()
	if _, err := strategy.Token(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid profile: error = %v, want %v", err, ErrInvalid)
	}
}

func TestDeviceRefreshLockPreventsReplay(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/oauth/token" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if ua := r.Header.Get("User-Agent"); !isStackAuthGoAgent(ua) {
			t.Errorf("device-session refresh User-Agent = %q, want stack-auth/<version> (Go)", ua)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		want := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"refresh-1"}, "client_id": {"client-1"}}
		if !reflect.DeepEqual(r.PostForm, want) {
			t.Errorf("request body = %v, want %v", r.PostForm, want)
		}
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	defer server.Close()
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			profile, err := Open(context.Background(), dir)
			if err != nil {
				errCh <- err
				return
			}
			defer profile.Close()
			ws, err := profile.WorkspaceStore(context.Background(), wsA)
			if err != nil {
				errCh <- err
				return
			}
			strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
			if err != nil {
				errCh <- err
				return
			}
			defer strategy.Close()
			token, err := strategy.Token(context.Background())
			if err == nil && token != "fresh" {
				err = fmt.Errorf("token = %q, want fresh", token)
			}
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Error(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh requests = %d, want 1", calls.Load())
	}
	data, err := os.ReadFile(filepath.Join(dir, "workspaces", wsA, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["refresh_token"] != "refresh-2" {
		t.Fatalf("stored refresh token = %v", stored["refresh_token"])
	}
}

func TestDeviceRefreshReportsInvalidGrant(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer server.Close()
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Token error = %v, want ErrInvalidGrant", err)
	}
	wantCode(t, err, "stack_auth::invalid_grant")
}

// The edge in front of production CTS answers a request whose User-Agent is
// Go's default (Go-http-client/1.1) with a bare nginx 403 before CTS sees
// it, and Go's HTTP client fills that default in when a request carries
// none. The access-key exchange must name stack-auth and the Go host.
func TestAuthRequestsIdentifyTheLibraryNotGo(t *testing.T) {
	guestOrSkip(t)
	var agent atomic.Value
	var jwt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent.Store(r.Header.Get("User-Agent"))
		if ua := r.Header.Get("User-Agent"); ua == "" || strings.HasPrefix(ua, "Go-http-client/") {
			// What the production edge does, so the failure is the real one.
			http.Error(w, "<html><center><h1>403 Forbidden</h1></center></html>", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	jwt = testJWT(t, server.URL)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	got, err := strategy.Token(context.Background())
	ua, _ := agent.Load().(string)
	if err != nil || got != jwt {
		t.Fatalf("Token = %q, %v (User-Agent %q)", got, err, ua)
	}
	if !isStackAuthGoAgent(ua) {
		t.Fatalf("User-Agent = %q, want stack-auth/<version> (Go)", ua)
	}
}

// isStackAuthGoAgent reports whether ua is the credential guest's own,
// stack-auth/<version> (Go), and not Go's default Go-http-client/1.1.
func isStackAuthGoAgent(ua string) bool {
	version, ok := strings.CutPrefix(ua, "stack-auth/")
	if !ok {
		return false
	}
	version, ok = strings.CutSuffix(version, " (Go)")
	return ok && version != "" && !strings.ContainsAny(version, " ()")
}

// A refused exchange says which HTTP status refused it, and never carries
// the response body: not in the message, and not in the Diagnostic.
func TestAuthTransportErrorNamesTheHTTPStatusNotTheBody(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><h1>403 Forbidden</h1>nginx CSAKtestKeyId.testKeySecret</html>")
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("Token error = %v, want ErrTransport", err)
	}
	if want := "Server error: 403: HTTP 403"; err.Error() != want {
		t.Fatalf("Token error = %q, want %q", err, want)
	}
	var d *Diagnostic
	if !errors.As(err, &d) || d.Code != "stack_auth::server_error" {
		t.Fatalf("Token error = %#v, want a stack_auth::server_error Diagnostic", err)
	}
	if shown := fmt.Sprintf("%+v", *d); strings.Contains(shown, "nginx") || strings.Contains(shown, "testKeySecret") {
		t.Fatalf("the response body is in the Diagnostic: %s", shown)
	}
}

// A transport failure with no HTTP response at all names no status: there
// is none to name. It is the guest's request error, over ErrTransport.
func TestAuthTransportErrorWithoutAResponseNamesNoStatus(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.NotFoundHandler())
	addr := server.URL
	server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "HTTP") {
		t.Fatalf("Token error = %v, want ErrTransport naming no status", err)
	}
	wantCode(t, err, "stack_auth::request_error")
}

// The host's transport error stays out of the Diagnostic: a RoundTripper's
// or a proxy's text can carry a URL's query string or proxy credentials.
func TestAuthTransportErrorTextIsNotInTheDiagnostic(t *testing.T) {
	guestOrSkip(t)
	ctx := context.Background()
	const marker = "leak-marker-transport"
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New(`Post "https://cts.invalid/token?secret=` + marker + `": proxyconnect tcp: refused`)
	})
	profile, err := Open(ctx, t.TempDir(), WithRoundTripper(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(ctx, testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL("https://cts.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(ctx)
	var d *Diagnostic
	if !errors.Is(err, ErrTransport) || !errors.As(err, &d) {
		t.Fatalf("Token error = %#v, want a Diagnostic over ErrTransport", err)
	}
	if shown := fmt.Sprintf("%v %+v", err, *d); strings.Contains(shown, marker) {
		t.Fatalf("the host's transport error is in the Diagnostic: %s", shown)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A status that would wrap in the guest's i32 — here to 200 — is refused
// as a transport failure, so a failed exchange cannot pass as a success.
func TestOutOfRangeAuthStatusIsTransport(t *testing.T) {
	guestOrSkip(t)
	cases := map[string]int{"negative": -200, "two digits": 99, "four digits": 1000}
	if strconv.IntSize == 64 {
		wraps := int64(1<<32 + 200)
		cases["wraps to 200"] = int(wraps)
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"accessToken":"x","expiry":0}`)),
				}, nil
			})
			profile, err := Open(ctx, t.TempDir(), WithRoundTripper(rt))
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Close()
			strategy, err := profile.AccessKey(ctx, testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL("https://cts.invalid"))
			if err != nil {
				t.Fatal(err)
			}
			defer strategy.Close()
			if _, err := strategy.Token(ctx); !errors.Is(err, ErrTransport) {
				t.Fatalf("Token: %v, want ErrTransport", err)
			}
		})
	}
}

// A store with no profile mounted still runs the strategies that need none:
// the environment's access key through Auto, as stack-auth's AutoStrategy
// does with no profile store. Profile reads are ErrNoProfile, and Auto with
// no access key is ErrNotAuthenticated rather than a profile error.
func TestOpenWithoutProfileRunsAccessKeyAndRefusesProfileReads(t *testing.T) {
	guestOrSkip(t)
	var jwt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	jwt = testJWT(t, server.URL)
	ctx := context.Background()
	store, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.Dir() != "" {
		t.Errorf("Dir = %q, want empty", store.Dir())
	}
	if _, err := store.CurrentWorkspace(ctx); !errors.Is(err, ErrNoProfile) {
		t.Errorf("CurrentWorkspace: %v, want ErrNoProfile", err)
	}
	if _, _, err := store.SecretKey(ctx); !errors.Is(err, ErrNoProfile) {
		t.Errorf("SecretKey: %v, want ErrNoProfile", err)
	}
	t.Setenv("CS_CLIENT_ACCESS_KEY", "CSAKtestKeyId.testKeySecret")
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	strategy, err := store.Auto(ctx, WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	if token, err := strategy.Token(ctx); err != nil || token != jwt {
		t.Fatalf("Token = %q, %v", token, err)
	}
	if err := os.Unsetenv("CS_CLIENT_ACCESS_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Auto(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Auto with no key and no profile: %v, want ErrNotAuthenticated", err)
	}
}

// A strategy reports its store's memory lock, asked live: a store opened
// best effort whose guest later grows into memory it cannot lock is
// reported unlocked by its strategies from then on.
func TestStrategyReportsItsStoresMemoryLockLive(t *testing.T) {
	ctx := context.Background()
	_, s := profile(t)
	strategy, err := s.AccessKey(ctx, testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL("https://cts.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	if fmt.Sprint(strategy.MemoryLockError()) != fmt.Sprint(s.MemoryLockError()) {
		t.Fatalf("Strategy.MemoryLockError = %v, want the store's %v", strategy.MemoryLockError(), s.MemoryLockError())
	}
	if s.MemoryLockError() != nil {
		t.Skipf("the store is unlocked already here (%v); a later refusal cannot be told apart", s.MemoryLockError())
	}
	unlocked := guest.UnlockGrowth(s.root.inst.mem, errors.New("refused for the test"))
	// Staging a 2 MiB argument into guest memory needs a growth.
	if _, err := s.call(ctx, func(i *instance) api.Function { return i.setCurrentWorkspace }, strings.Repeat("A", 2<<20)); errors.Is(err, ErrMemoryLock) {
		t.Fatalf("a best-effort growth was refused: %v", err)
	}
	if unlocked.Refused() == 0 {
		t.Fatal("the guest did not grow; the test proves nothing")
	}
	if err := strategy.MemoryLockError(); !errors.Is(err, ErrMemoryLock) || !strings.Contains(err.Error(), unlocked.Reason().Error()) {
		t.Fatalf("Strategy.MemoryLockError after an unlocked growth = %v, want ErrMemoryLock naming it", err)
	}
	_ = strategy.Close()
	if err := strategy.MemoryLockError(); !errors.Is(err, ErrMemoryLock) {
		t.Fatalf("Strategy.MemoryLockError after Close = %v, want the store's report still", err)
	}
}
