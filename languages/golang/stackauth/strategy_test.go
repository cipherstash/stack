package stackauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testCRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"

func testJWT(t *testing.T, issuer string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "sub": "CS|test", "workspace": "ZVATKW3VHMFG27DY",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
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
		if body["accessKey"] != "CSAKtestKeyId.testKeySecret" {
			t.Errorf("body: %#v", body)
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
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithAuthBaseURL(server.URL))
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

func TestOIDCStrategyCallsProviderOnlyOnExchange(t *testing.T) {
	guestOrSkip(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["oidcToken"] != "idp-token" || body["workspaceId"] != "ZVATKW3VHMFG27DY" {
			t.Errorf("body: %#v", body)
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWT(t, "https://cts.example"), time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.OIDC(context.Background(), testCRN, OIDCProviderFunc(func(context.Context) (string, error) {
		calls.Add(1)
		return "idp-token", nil
	}), WithAuthBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	for i := 0; i < 2; i++ {
		if _, err := strategy.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", calls.Load())
	}
}

func TestAuthErrorTaxonomy(t *testing.T) {
	guestOrSkip(t)
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"usage limit", 402, `{"cs_code":"USAGE_LIMIT_EXCEEDED"}`, ErrUsageLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			profile, err := Open(context.Background(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Close()
			strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithAuthBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer strategy.Close()
			_, err = strategy.Token(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Token error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDeviceRefreshInvalidClient(t *testing.T) {
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
	strategy, err := ws.DeviceSession(context.Background(), WithAuthBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Token error = %v, want %v", err, ErrInvalidClient)
	}
}

// Match stack-auth's AutoStrategy order: an access key wins over a stored
// device session; with no key, the current workspace's auth.json is used.
func TestAutoStrategyDetectionOrder(t *testing.T) {
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
	strategy, err := profile.Auto(context.Background(), WithAuthBaseURL(server.URL))
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
	t.Setenv("CS_CLIENT_ACCESS_KEY", "")
	strategy, err = profile.Auto(context.Background(), WithAuthBaseURL(server.URL))
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
	if _, err := profile.Auto(context.Background(), WithAuthBaseURL(server.URL)); !errors.Is(err, ErrNotAuthenticated) {
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

func TestDeviceRefreshLockPreventsReplay(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/oauth/token" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-1" || r.Form.Get("client_id") != "client-1" {
			t.Errorf("form: %v", r.Form)
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
			strategy, err := ws.DeviceSession(context.Background(), WithAuthBaseURL(server.URL))
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

func TestDeviceRefreshInvalidGrant(t *testing.T) {
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
	strategy, err := ws.DeviceSession(context.Background(), WithAuthBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	_, err = strategy.Token(context.Background())
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Token error = %v, want ErrInvalidGrant", err)
	}
}
