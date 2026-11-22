package auth

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
	"sync"
	"testing"
	"time"
)

// The workspace of the saved session in these tests, and its CRN. It is not
// testCRN's workspace, so a test can tell which source a CRN came from.
const testSessionCRN = "crn:ap-southeast-2.aws:" + wsA

// workspaceCTS is a CTS that federates any IdP token into a CTS token for
// the workspace the request names, and records each workspace it was asked
// for. The strategy checks a token's workspace against the one it expects,
// so a token for the requested workspace is the only one it accepts.
type workspaceCTS struct {
	*httptest.Server
	mu         sync.Mutex
	workspaces []string
}

func newWorkspaceCTS(t *testing.T) *workspaceCTS {
	t.Helper()
	cts := &workspaceCTS{}
	cts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			WorkspaceID string `json:"workspaceId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		cts.mu.Lock()
		cts.workspaces = append(cts.workspaces, body.WorkspaceID)
		cts.mu.Unlock()
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwtForWorkspace(t, body.WorkspaceID), time.Now().Add(time.Hour).Unix())
	}))
	t.Cleanup(cts.Close)
	return cts
}

// asked is the workspaces the CTS was asked for, in order.
func (c *workspaceCTS) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.workspaces...)
}

// jwtForWorkspace is an unsigned JWT whose workspace claim is workspace.
func jwtForWorkspace(t *testing.T, workspace string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": "https://cts.example", "sub": "CS|test", "workspace": workspace,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// unsetEnv unsets name for the rest of the test, and restores it after.
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// sessionJSON is the auth.json `stash auth login` saves for workspace wsA,
// recording region, or no region when region is empty.
func sessionJSON(t *testing.T, region string) string {
	t.Helper()
	regionJSON := "null"
	if region != "" {
		regionJSON = fmt.Sprintf("%q", region)
	}
	return fmt.Sprintf(`{"access_token":%q,"refresh_token":"refresh","token_type":"Bearer","expires_at":%d,"region":%s,"client_id":"cli"}`,
		jwtForWorkspace(t, wsA), time.Now().Add(time.Hour).Unix(), regionJSON)
}

// loggedInProfile is a profile directory whose current workspace is wsA,
// with auth as its saved session when auth is not empty.
func loggedInProfile(t *testing.T, auth string) string {
	t.Helper()
	dir := t.TempDir()
	ws := filepath.Join(dir, "workspaces", wsA)
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "current_workspace"), wsA)
	if auth != "" {
		write(t, filepath.Join(ws, "auth.json"), auth)
	}
	return dir
}

// brokenProfile is a profile directory whose current_workspace file does not
// hold a workspace id. Reading it is ErrInvalidWorkspaceID, so a test that
// succeeds over it did not read the profile.
func brokenProfile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "current_workspace"), "not-a-workspace")
	return dir
}

func openProfile(t *testing.T, dir string) *ProfileStore {
	t.Helper()
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = profile.Close() })
	return profile
}

var anyIdPToken = OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil })

// federatesFor builds a strategy with build, gets a token from it, and
// checks that CTS was asked for workspace and nothing else.
func federatesFor(t *testing.T, cts *workspaceCTS, workspace string, build func() (*Strategy, error)) {
	t.Helper()
	strategy, err := build()
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	if _, err := strategy.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got := cts.asked(); len(got) != 1 || got[0] != workspace {
		t.Fatalf("CTS was asked for workspaces %v, want [%s]", got, workspace)
	}
}

func TestOIDCWithDetectedWorkspaceUsesTheVariableWithoutReadingTheProfile(t *testing.T) {
	guestOrSkip(t)
	cts := newWorkspaceCTS(t)
	profile := openProfile(t, brokenProfile(t))
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	federatesFor(t, cts, "ZVATKW3VHMFG27DY", func() (*Strategy, error) {
		return profile.OIDCWithDetectedWorkspace(context.Background(), anyIdPToken, WithBaseURL(cts.URL))
	})
}

// A CS_WORKSPACE_CRN that is not a CRN is an error even beside a profile
// with a valid session: it is never a reason to use the profile's.
func TestOIDCWithDetectedWorkspaceRefusesAnInvalidVariable(t *testing.T) {
	guestOrSkip(t)
	profile := openProfile(t, loggedInProfile(t, sessionJSON(t, "ap-southeast-2.aws")))
	t.Setenv("CS_WORKSPACE_CRN", "not-a-crn")
	_, err := profile.OIDCWithDetectedWorkspace(context.Background(), anyIdPToken, WithBaseURL("https://cts.example.com"))
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want %v", err, ErrConfig)
	}
	wantCode(t, err, "stack_auth::invalid_crn")
	if !strings.Contains(err.Error(), "CS_WORKSPACE_CRN") {
		t.Errorf("error %q does not name CS_WORKSPACE_CRN", err)
	}
}

func TestOIDCWithDetectedWorkspaceUsesTheCurrentWorkspacesSession(t *testing.T) {
	guestOrSkip(t)
	unsetEnv(t, "CS_WORKSPACE_CRN")
	cts := newWorkspaceCTS(t)
	profile := openProfile(t, loggedInProfile(t, sessionJSON(t, "ap-southeast-2.aws")))
	federatesFor(t, cts, wsA, func() (*Strategy, error) {
		return profile.OIDCWithDetectedWorkspace(context.Background(), anyIdPToken, WithBaseURL(cts.URL))
	})
	crn, err := profile.detectWorkspaceCRN(context.Background())
	if err != nil || crn != testSessionCRN {
		t.Fatalf("detected CRN = %q, %v; want %q", crn, err, testSessionCRN)
	}
}

// With no variable and no saved session to read, the error is
// ErrNotAuthenticated and says what to do.
func TestOIDCWithDetectedWorkspaceWithNeitherIsNotAuthenticated(t *testing.T) {
	guestOrSkip(t)
	unsetEnv(t, "CS_WORKSPACE_CRN")
	cases := []struct {
		name string
		open func(t *testing.T) *ProfileStore
	}{
		{"no current workspace", func(t *testing.T) *ProfileStore {
			return openProfile(t, t.TempDir())
		}},
		{"a current workspace with no saved session", func(t *testing.T) *ProfileStore {
			return openProfile(t, loggedInProfile(t, ""))
		}},
		{"a saved session that records no region", func(t *testing.T) *ProfileStore {
			return openProfile(t, loggedInProfile(t, sessionJSON(t, "")))
		}},
		{"no profile", func(t *testing.T) *ProfileStore {
			profile, err := OpenWithoutProfile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = profile.Close() })
			return profile
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := tc.open(t)
			_, err := profile.OIDCWithDetectedWorkspace(context.Background(), anyIdPToken, WithBaseURL("https://cts.example.com"))
			if !errors.Is(err, ErrNotAuthenticated) {
				t.Fatalf("error = %v, want %v", err, ErrNotAuthenticated)
			}
			for _, hint := range []string{"CS_WORKSPACE_CRN", "stash auth login"} {
				if !strings.Contains(err.Error(), hint) {
					t.Errorf("error %q does not mention %s", err, hint)
				}
			}
		})
	}
}

// A profile that is there but cannot be read is reported as itself, never as
// not logged in.
func TestOIDCWithDetectedWorkspaceReportsABrokenProfileAsItself(t *testing.T) {
	guestOrSkip(t)
	unsetEnv(t, "CS_WORKSPACE_CRN")
	cases := []struct {
		name    string
		profile func(t *testing.T) string
		want    error
		code    string
	}{
		{"a current workspace that is not a workspace id", brokenProfile, ErrInvalidWorkspaceID, "stack_profile::invalid_workspace_id"},
		{"a current_workspace file that cannot be read", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "current_workspace"), 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}, ErrIO, "stack_profile::io"},
		{"a saved session that is not JSON", func(t *testing.T) string {
			return loggedInProfile(t, "{")
		}, ErrInvalid, "stack_profile::json"},
		{"a saved session whose token is not a JWT", func(t *testing.T) string {
			return loggedInProfile(t, fmt.Sprintf(`{"access_token":"not-a-jwt","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2.aws"}`,
				time.Now().Add(time.Hour).Unix()))
		}, ErrInvalid, "stack_auth::invalid_token"},
		{"a saved session whose region is not a region", func(t *testing.T) string {
			return loggedInProfile(t, sessionJSON(t, "nowhere"))
		}, ErrInvalid, "stack_auth::invalid_region"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := openProfile(t, tc.profile(t))
			_, err := profile.OIDCWithDetectedWorkspace(context.Background(), anyIdPToken, WithBaseURL("https://cts.example.com"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if errors.Is(err, ErrNotAuthenticated) {
				t.Fatalf("a broken profile reads as not logged in: %v", err)
			}
			wantCode(t, err, tc.code)
		})
	}
}

// Naming the CRN reads neither the variable nor the profile.
func TestOIDCWithANamedCRNIgnoresTheVariableAndTheProfile(t *testing.T) {
	guestOrSkip(t)
	cts := newWorkspaceCTS(t)
	profile := openProfile(t, brokenProfile(t))
	t.Setenv("CS_WORKSPACE_CRN", "not-a-crn")
	federatesFor(t, cts, "ZVATKW3VHMFG27DY", func() (*Strategy, error) {
		return profile.OIDC(context.Background(), testCRN, anyIdPToken, WithBaseURL(cts.URL))
	})
}

func TestOIDCWithDetectedWorkspaceNeedsAProvider(t *testing.T) {
	guestOrSkip(t)
	profile := openProfile(t, t.TempDir())
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	if _, err := profile.OIDCWithDetectedWorkspace(context.Background(), nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil provider: error = %v, want %v", err, ErrConfig)
	}
}

// A workspace store has no current workspace of its own, so it cannot detect
// one; it is refused rather than reported as not logged in.
func TestOIDCWithDetectedWorkspaceRefusesAWorkspaceStore(t *testing.T) {
	guestOrSkip(t)
	unsetEnv(t, "CS_WORKSPACE_CRN")
	profile := openProfile(t, loggedInProfile(t, sessionJSON(t, "ap-southeast-2.aws")))
	ctx := context.Background()
	current, err := profile.CurrentWorkspaceStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	named, err := profile.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]*ProfileStore{"CurrentWorkspaceStore": current, "WorkspaceStore": named} {
		_, err := store.OIDCWithDetectedWorkspace(ctx, anyIdPToken, WithBaseURL("https://cts.example.com"))
		if !errors.Is(err, ErrConfig) {
			t.Errorf("%s: error = %v, want %v", name, err, ErrConfig)
		}
	}
}
