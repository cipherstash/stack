package stackencrypt

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackauth"
)

// Credential resolution, pinned against the Rust client's order. The
// sources the order is taken from, so a change there is a change here:
//
//   - the token: stack-auth's AutoStrategy::detect_inner — an access key
//     from CS_CLIENT_ACCESS_KEY (CS_WORKSPACE_CRN then required), else the
//     current workspace's auth.json, else NotAuthenticated;
//   - the client key: stack-encrypt's client_key_provider (cipher.rs) —
//     FallbackKeyProvider(EnvKeyProvider, the profile), falling through only
//     on "not configured": both CS_CLIENT_ID and CS_CLIENT_KEY set, else the
//     current workspace's secretkey.json; a set but unusable value is an
//     error, not a fall-through; an unresolvable profile is not an error;
//   - the order of the two: StackCipherBuilder::init detects the strategy
//     (StackKmsBuilder::auto) before it asks the key provider (build);
//   - the endpoint: stack-kms's StackKmsBuilder::base_url_from_env — an
//     explicit URL, else the first of CS_ZEROKMS_HOST and CS_VITUR_HOST that
//     is set, an unusable value an error; else the token's services claim.

const (
	testCRN       = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
	testAccessKey = "CSAKtestKeyId.testKeySecret"
	testWorkspace = "AAAAAAAAAAAAAAAA"
	// The profile's client id: distinct from testClientID, so a test can
	// tell which source a key came from.
	profileClientID = "0b1e8a44-5c1d-4d4e-9b52-3f0e6c2f8a17"
)

// authGuestOrSkip skips where stackauth's credential guest is not built,
// as guestOrSkip does for this package's own.
func authGuestOrSkip(t *testing.T) {
	t.Helper()
	store, err := stackauth.OpenWithoutProfile(context.Background())
	if errors.Is(err, stackauth.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
}

// cleanEnv clears every variable credential resolution reads, and points
// the profile at dir, so no test sees the developer's own credentials.
// t.Setenv restores each at the end of the test.
func cleanEnv(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{
		envClientID, envClientKey, envAccessKey, envWorkspaceCRN,
		"CS_ZEROKMS_HOST", "CS_VITUR_HOST", "CS_CTS_HOST", "CS_CONFIG_PATH",
	} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CS_CONFIG_PATH", dir)
	// The stored test tokens are not JWTs, so the device session cannot
	// discover CTS from one; name it. Nothing is sent there while a token
	// is fresh. newAuthServer points it at itself.
	t.Setenv("CS_CTS_HOST", "https://cts.example.com")
}

// profileFiles is what a login leaves in a workspace. An empty field is a
// file not written.
type profileFiles struct {
	secretKey string
	auth      string
}

// loggedIn is the profile `stash auth login` leaves: a current workspace
// holding the test client key under profileClientID and a fresh token.
func loggedIn(token string) profileFiles {
	return profileFiles{
		secretKey: fmt.Sprintf(`{"client_id":%q,"client_key":%q}`, profileClientID,
			base64.StdEncoding.EncodeToString(mustHex(testClientKey))),
		auth: fmt.Sprintf(`{"access_token":%q,"refresh_token":"refresh","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2.aws","client_id":"cli"}`,
			token, time.Now().Add(time.Hour).Unix()),
	}
}

// newProfile writes a profile directory with testWorkspace current and
// files in it, and returns the directory.
func newProfile(t *testing.T, files profileFiles) string {
	t.Helper()
	dir := t.TempDir()
	ws := filepath.Join(dir, "workspaces", testWorkspace)
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"secretkey.json": files.secretKey, "auth.json": files.auth} {
		if content != "" {
			if err := os.WriteFile(filepath.Join(ws, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	store, err := stackauth.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetCurrentWorkspace(context.Background(), testWorkspace); err != nil {
		t.Fatal(err)
	}
	return dir
}

// authServer is CTS's access-key exchange: it answers every /api/authorise
// with a fresh JWT, and counts the exchanges.
type authServer struct {
	*httptest.Server
	jwt   string
	calls atomic.Int32
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	s := &authServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/authorise" {
			t.Errorf("unexpected auth request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		s.calls.Add(1)
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, s.jwt, time.Now().Add(time.Hour).Unix())
	}))
	t.Cleanup(s.Close)
	payload, err := json.Marshal(map[string]any{
		"iss": s.URL, "sub": "CS|test", "workspace": "ZVATKW3VHMFG27DY",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.jwt = "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
	t.Setenv("CS_CTS_HOST", s.URL)
	return s
}

// resolve runs AutoCredentials and releases what it holds at the end of
// the test.
func resolve(t *testing.T) (*ResolvedCredentials, error) {
	t.Helper()
	resolved, err := AutoCredentials().Resolve(context.Background(), ResolveOptions{Transport: http.DefaultTransport})
	if err == nil {
		t.Cleanup(func() { _ = resolved.Close() })
	}
	return resolved, err
}

func token(t *testing.T, resolved *ResolvedCredentials) string {
	t.Helper()
	tok, err := resolved.Token.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return tok
}

func TestAutoCredentialsFromTheProfile(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	resolved, err := resolve(t)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ClientID != profileClientID {
		t.Errorf("ClientID = %q, want the profile's", resolved.ClientID)
	}
	if got := string(guest.KeyBytes(resolved.ClientKey)); got != base64.StdEncoding.EncodeToString(mustHex(testClientKey)) {
		t.Error("ClientKey is not the profile's secretkey.json")
	}
	if got := token(t, resolved); got != "profile-token" {
		t.Errorf("Token = %q, want the stored device session's", got)
	}
}

func TestAutoCredentialsFromTheEnvironmentWithNoProfile(t *testing.T) {
	authGuestOrSkip(t)
	// The CI shape: four variables and no profile directory at all.
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	auth := newAuthServer(t)
	t.Setenv(envAccessKey, testAccessKey)
	t.Setenv(envWorkspaceCRN, testCRN)
	t.Setenv(envClientID, testClientID)
	t.Setenv(envClientKey, testClientKey)
	resolved, err := resolve(t)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ClientID != testClientID || string(guest.KeyBytes(resolved.ClientKey)) != testClientKey {
		t.Error("the client key is not the environment's")
	}
	if got := token(t, resolved); got != auth.jwt || auth.calls.Load() != 1 {
		t.Errorf("Token = %q after %d exchanges, want the access key's", got, auth.calls.Load())
	}
}

func TestAutoCredentialsPrecedence(t *testing.T) {
	authGuestOrSkip(t)
	t.Run("the environment's client key wins over the profile's", func(t *testing.T) {
		cleanEnv(t, newProfile(t, loggedIn("profile-token")))
		t.Setenv(envClientID, testClientID)
		t.Setenv(envClientKey, testClientKey)
		resolved, err := resolve(t)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.ClientID != testClientID || string(guest.KeyBytes(resolved.ClientKey)) != testClientKey {
			t.Error("the client key is not the environment's")
		}
		// The token still comes from the profile: the halves resolve apart.
		if got := token(t, resolved); got != "profile-token" {
			t.Errorf("Token = %q, want the profile's", got)
		}
	})
	t.Run("one of the two key variables is the same as neither", func(t *testing.T) {
		for _, name := range []string{envClientID, envClientKey} {
			cleanEnv(t, newProfile(t, loggedIn("profile-token")))
			value := testClientID
			if name == envClientKey {
				value = testClientKey
			}
			t.Setenv(name, value)
			resolved, err := resolve(t)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.ClientID != profileClientID {
				t.Errorf("only %s set: ClientID = %q, want the profile's", name, resolved.ClientID)
			}
		}
	})
	t.Run("the environment's access key wins over the stored session", func(t *testing.T) {
		cleanEnv(t, newProfile(t, loggedIn("profile-token")))
		auth := newAuthServer(t)
		t.Setenv(envAccessKey, testAccessKey)
		t.Setenv(envWorkspaceCRN, testCRN)
		resolved, err := resolve(t)
		if err != nil {
			t.Fatal(err)
		}
		if got := token(t, resolved); got != auth.jwt {
			t.Errorf("Token = %q, want the access key's", got)
		}
		// The key still comes from the profile.
		if resolved.ClientID != profileClientID {
			t.Errorf("ClientID = %q, want the profile's", resolved.ClientID)
		}
	})
}

func TestAutoCredentialsMissing(t *testing.T) {
	authGuestOrSkip(t)
	for _, tc := range []struct {
		name string
		// profile is nil for no profile directory at all.
		profile *profileFiles
		env     map[string]string
		want    []error
		names   string
	}{
		{
			name:  "nothing anywhere",
			want:  []error{ErrNoCredentials, stackauth.ErrNotAuthenticated},
			names: envAccessKey,
		},
		{
			name:    "a profile with no login",
			profile: &profileFiles{},
			want:    []error{ErrNoCredentials, stackauth.ErrNotAuthenticated},
			names:   "stash auth login",
		},
		{
			// The token is there and the key is not: the key's error, naming
			// the variables that would supply it.
			name:  "an access key and no client key",
			env:   map[string]string{envAccessKey: testAccessKey, envWorkspaceCRN: testCRN},
			want:  []error{ErrNoCredentials},
			names: envClientKey,
		},
		{
			name:    "a stored session and no secretkey.json",
			profile: &profileFiles{auth: loggedIn("t").auth},
			want:    []error{ErrNoCredentials, stackauth.ErrNotFound},
			names:   envClientKey,
		},
		{
			name: "an access key with no workspace CRN",
			env:  map[string]string{envAccessKey: testAccessKey, envClientID: testClientID, envClientKey: testClientKey},
			want: []error{stackauth.ErrAuthConfig},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "absent")
			if tc.profile != nil {
				dir = newProfile(t, *tc.profile)
			}
			cleanEnv(t, dir)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := resolve(t)
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Errorf("error %v, want %v", err, want)
				}
			}
			if err != nil && !strings.Contains(err.Error(), tc.names) {
				t.Errorf("error %q does not name %q", err, tc.names)
			}
		})
	}
}

// A set but empty variable is refused rather than skipped, as stack-kms's
// EnvKeyProvider refuses it; and no error from resolution carries the
// material of a key the environment or the profile held.
func TestAutoCredentialsRefusesAnEmptyKeyVariableWithoutPrintingKeys(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	t.Setenv(envClientID, "")
	t.Setenv(envClientKey, testClientKey)
	_, err := resolve(t)
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("empty %s: %v, want ErrEncoding, not the profile's key", envClientID, err)
	}
	profileKey := base64.StdEncoding.EncodeToString(mustHex(testClientKey))
	for _, leak := range []string{testClientKey[:16], profileKey[:16]} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the error carries key material: %q", err)
		}
	}
}

// The credentials NewClient resolved are the client's: the token source it
// asks is theirs, and Close releases them. Nothing printed of the client or
// of a failed NewClient carries the key.
func TestNewClientWithAutoCredentials(t *testing.T) {
	guestOrSkip(t)
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	// The endpoint from the environment, since the Config names none.
	t.Setenv("CS_ZEROKMS_HOST", stub.URL)
	var released *ResolvedCredentials
	creds := credentialsFunc(func(ctx context.Context, opts ResolveOptions) (*ResolvedCredentials, error) {
		r, err := AutoCredentials().Resolve(ctx, opts)
		released = r
		return r, err
	})
	_, err := NewClient(context.Background(), Config{Credentials: creds})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized from the stub", err)
	}
	if len(stub.requests) != 1 || stub.requests[0].auth != "Bearer profile-token" {
		t.Fatalf("requests = %+v, want one bearing the profile's token", stub.requests)
	}
	if strings.Contains(err.Error(), testClientKey[:16]) {
		t.Fatalf("the error carries key material: %q", err)
	}
	// A failed NewClient released the credentials it resolved.
	if _, err := released.Token.Token(context.Background()); !errors.Is(err, stackauth.ErrState) {
		t.Fatalf("the token source after a failed NewClient: %v, want ErrState", err)
	}
}

// A nil Credentials is AutoCredentials: with nothing configured, the error
// is the resolution's, before any guest or request.
func TestNewClientDefaultsToAutoCredentials(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	if _, err := NewClient(context.Background(), Config{}); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("NewClient with no credentials anywhere: %v, want ErrNoCredentials", err)
	}
}

func TestZeroKMSEndpointOrder(t *testing.T) {
	const explicit, primary, legacy = "https://explicit.example", "https://primary.example", "https://legacy.example"
	for _, tc := range []struct {
		name             string
		explicit         string
		primary, legacy  *string
		want             string
		wantErr, errName string
	}{
		{name: "none", want: ""},
		{name: "explicit wins", explicit: explicit, primary: ptr(primary), legacy: ptr(legacy), want: explicit},
		{name: "CS_ZEROKMS_HOST over the legacy name", primary: ptr(primary), legacy: ptr(legacy), want: primary},
		{name: "the legacy name alone", legacy: ptr(legacy), want: legacy},
		// Set decides, not non-empty: an empty primary is an error, and
		// the legacy name is not consulted.
		{name: "set but empty", primary: ptr(""), legacy: ptr(legacy), errName: "CS_ZEROKMS_HOST"},
		{name: "no scheme", primary: ptr("localhost:3002"), errName: "CS_ZEROKMS_HOST"},
		{name: "not http", legacy: ptr("ftp://zerokms.example"), errName: "CS_VITUR_HOST"},
		{name: "no host", primary: ptr("https://"), errName: "CS_ZEROKMS_HOST"},
		{name: "userinfo is not printed", primary: ptr("https://user:hunter2@%zz"), errName: "CS_ZEROKMS_HOST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t, t.TempDir())
			if tc.primary != nil {
				t.Setenv("CS_ZEROKMS_HOST", *tc.primary)
			}
			if tc.legacy != nil {
				t.Setenv("CS_VITUR_HOST", *tc.legacy)
			}
			got, err := zerokmsEndpoint(tc.explicit)
			if tc.errName != "" {
				if !errors.Is(err, ErrEncoding) || !strings.Contains(err.Error(), tc.errName) {
					t.Fatalf("error %v, want ErrEncoding naming %s", err, tc.errName)
				}
				if strings.Contains(err.Error(), "hunter2") {
					t.Fatalf("the error prints the URL: %q", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("zerokmsEndpoint = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// Close releases what the credentials hold: the token strategy and the
// profile's guest.
func TestAutoCredentialsCloseReleasesTheGuest(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	resolved, err := AutoCredentials().Resolve(context.Background(), ResolveOptions{Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolved.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := resolved.Token.Token(context.Background()); !errors.Is(err, stackauth.ErrState) {
		t.Fatalf("Token after Close: %v, want ErrState", err)
	}
}

func TestCredentialsPrintNoKey(t *testing.T) {
	for _, c := range []Credentials{AutoCredentials(), NewCredentials(testClientID, NewClientKey([]byte(testClientKey)), StaticToken("t"))} {
		for _, verb := range []string{"%v", "%+v", "%s"} {
			if out := fmt.Sprintf(verb, c); strings.Contains(out, testClientKey[:16]) || !strings.HasPrefix(out, "stackencrypt.") {
				t.Errorf("%s: %q", verb, out)
			}
		}
	}
}

type credentialsFunc func(context.Context, ResolveOptions) (*ResolvedCredentials, error)

func (f credentialsFunc) Resolve(ctx context.Context, opts ResolveOptions) (*ResolvedCredentials, error) {
	return f(ctx, opts)
}

func ptr(s string) *string { return &s }
