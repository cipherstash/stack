package encrypt

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

var idpToken = auth.OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil })

func resolveDetected(t *testing.T) (*resolvedCredentials, error) {
	t.Helper()
	resolved, err := OIDCFederationWithDetectedWorkspace(idpToken).resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if err == nil {
		t.Cleanup(func() { _ = resolved.Close() })
	}
	return resolved, err
}

// With CS_WORKSPACE_CRN set and no profile at all, the variable names the
// workspace the token is federated into.
func TestOIDCFederationWithDetectedWorkspaceTakesTheVariable(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	cts := newAuthServer(t)
	t.Setenv(envWorkspaceCRN, testCRN)
	t.Setenv(envClientID, testClientID)
	t.Setenv(envClientKey, testClientKey)
	resolved, err := resolveDetected(t)
	if err != nil {
		t.Fatal(err)
	}
	resolved.ClientKey.Wipe()
	if got := token(t, resolved); got != cts.jwt {
		t.Fatalf("token = %q, want the federated one", got)
	}
}

// With no variable, the workspace is the one the CLI's saved session names,
// and the client key comes from the same profile.
func TestOIDCFederationWithDetectedWorkspaceTakesTheCLISession(t *testing.T) {
	authGuestOrSkip(t)
	// The session's token names testCRN's workspace, which is the one the
	// test CTS mints tokens for. A token for any other workspace is refused.
	cts := newAuthServer(t)
	cleanEnv(t, newProfile(t, loggedIn(cts.jwt)))
	t.Setenv("CS_CTS_HOST", cts.URL)
	resolved, err := resolveDetected(t)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ClientID != profileClientID || guest.KeyBytes(resolved.ClientKey) == nil {
		t.Errorf("ClientID = %q, want the profile's", resolved.ClientID)
	}
	resolved.ClientKey.Wipe()
	if got := token(t, resolved); got != cts.jwt {
		t.Fatalf("token = %q, want the federated one", got)
	}
}

func TestOIDCFederationWithDetectedWorkspaceWithNeitherIsNoCredentials(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	t.Setenv(envClientID, testClientID)
	t.Setenv(envClientKey, testClientKey)
	_, err := resolveDetected(t)
	if !errors.Is(err, ErrNoCredentials) || !errors.Is(err, auth.ErrNotAuthenticated) {
		t.Fatalf("error = %v, want ErrNoCredentials and auth.ErrNotAuthenticated", err)
	}
	// What to do, and why the profile was not read.
	for _, want := range []string{envWorkspaceCRN, "stash auth login", "absent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

// A CS_WORKSPACE_CRN that is not a CRN is a configuration error, never a
// reason to use the profile's workspace.
func TestOIDCFederationWithDetectedWorkspaceRefusesAnInvalidVariable(t *testing.T) {
	authGuestOrSkip(t)
	cts := newAuthServer(t)
	cleanEnv(t, newProfile(t, loggedIn(cts.jwt)))
	t.Setenv(envWorkspaceCRN, "not-a-crn")
	_, err := resolveDetected(t)
	if !errors.Is(err, auth.ErrConfig) || errors.Is(err, ErrNoCredentials) {
		t.Fatalf("error = %v, want auth.ErrConfig", err)
	}
	if cts.calls.Load() != 0 {
		t.Fatalf("exchanges: %d, want none", cts.calls.Load())
	}
}

func TestOIDCFederationWithDetectedWorkspaceIsComparableAndPrintable(t *testing.T) {
	a := OIDCFederationWithDetectedWorkspace(nil)
	b := OIDCFederationWithDetectedWorkspace(nil)
	if a == b {
		t.Fatal("two credentials compare equal")
	}
	_ = map[Credentials]bool{a: true, b: true}
	if got := a.(*detectedOIDCCredentials).String(); got != "encrypt.OIDCFederationWithDetectedWorkspace" {
		t.Fatalf("String() = %q", got)
	}
}
