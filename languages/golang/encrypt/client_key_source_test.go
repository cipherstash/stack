package encrypt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

// The client key sources, pinned against stack-kms's key providers:
// ClientKeyFromEnv is EnvKeyProvider, ClientKeyFromProfile is
// ProfileKeyProvider::for_workspace (never another workspace's key in its
// place), and ClientKeyFromValues is StaticKeyProvider.

const (
	// testCRNWorkspace is the workspace testCRN names. newProfile makes
	// testWorkspace current, so the two differ.
	testCRNWorkspace = "ZVATKW3VHMFG27DY"
	// namedClientID is the client id addWorkspaceKey writes: distinct from
	// profileClientID and testClientID, so a test can tell which source a
	// key came from.
	namedClientID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
)

// addWorkspaceKey writes secretkey.json for workspace into the profile at
// dir, under clientID. It does not change the current workspace.
func addWorkspaceKey(t *testing.T, dir, workspace, clientID string) {
	t.Helper()
	ws := filepath.Join(dir, "workspaces", workspace)
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`{"client_id":%q,"client_key":%q}`, clientID,
		base64.StdEncoding.EncodeToString(mustHex(testClientKey)))
	if err := os.WriteFile(filepath.Join(ws, "secretkey.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// oidcWith is OIDCFederation for testCRN with key as its client key source,
// and a provider that is never asked: resolving builds the strategy, but
// asks for no token.
func oidcWith(key ClientKeySource) *OIDCFederationCredentials {
	provider := auth.OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil })
	return OIDCFederation(testCRN, provider).WithClientKey(key)
}

// resolveCreds resolves creds and releases what they hold at the end of the
// test.
func resolveCreds(t *testing.T, creds Credentials) (*resolvedCredentials, error) {
	t.Helper()
	resolved, err := creds.resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if err == nil {
		t.Cleanup(func() { _ = resolved.Close() })
	}
	return resolved, err
}

// setUnusableKeyVariables sets the key variables to values that are an
// error if they are read: a source that reads them fails.
func setUnusableKeyVariables(t *testing.T) {
	t.Helper()
	t.Setenv(envClientID, "")
	t.Setenv(envClientKey, testClientKey)
}

func TestClientKeyFromProfileReadsOnlyTheNamedWorkspace(t *testing.T) {
	authGuestOrSkip(t)
	t.Run("the named workspace's key, with another workspace current", func(t *testing.T) {
		dir := newProfile(t, loggedIn("profile-token"))
		addWorkspaceKey(t, dir, testCRNWorkspace, namedClientID)
		cleanEnv(t, dir)
		setUnusableKeyVariables(t)
		resolved, err := resolveCreds(t, oidcWith(ClientKeyFromProfile(testCRN)))
		if err != nil {
			t.Fatalf("resolve: %v (the environment was read, or the key was not found)", err)
		}
		if resolved.ClientID != namedClientID {
			t.Errorf("ClientID = %q, want the named workspace's %q", resolved.ClientID, namedClientID)
		}
		if got := string(guest.KeyBytes(resolved.ClientKey)); got != base64.StdEncoding.EncodeToString(mustHex(testClientKey)) {
			t.Error("ClientKey is not the named workspace's secretkey.json")
		}
	})
	t.Run("the named workspace has no key: never the current workspace's", func(t *testing.T) {
		// The current workspace has a key. The named one does not.
		cleanEnv(t, newProfile(t, loggedIn("profile-token")))
		t.Setenv(envClientID, testClientID)
		t.Setenv(envClientKey, testClientKey)
		resolved, err := resolveCreds(t, oidcWith(ClientKeyFromProfile(testCRN)))
		if err == nil {
			t.Fatalf("resolved with ClientID %q, want no key", resolved.ClientID)
		}
		for _, want := range []error{ErrNoCredentials, auth.ErrNotFound} {
			if !errors.Is(err, want) {
				t.Errorf("error %v, want %v", err, want)
			}
		}
		if !strings.Contains(err.Error(), testCRN) || !strings.Contains(err.Error(), "stash auth login") {
			t.Errorf("error %q does not name the workspace and the fix", err)
		}
		if strings.Contains(err.Error(), envClientKey) {
			t.Errorf("error %q suggests the environment, which this source does not read", err)
		}
	})
	t.Run("no profile directory", func(t *testing.T) {
		cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
		_, err := resolveCreds(t, oidcWith(ClientKeyFromProfile(testCRN)))
		for _, want := range []error{ErrNoCredentials, auth.ErrNoProfile} {
			if !errors.Is(err, want) {
				t.Errorf("error %v, want %v", err, want)
			}
		}
	})
	t.Run("a value that is not a CRN", func(t *testing.T) {
		cleanEnv(t, newProfile(t, loggedIn("profile-token")))
		_, err := resolveCreds(t, oidcWith(ClientKeyFromProfile(testCRNWorkspace)))
		if !errors.Is(err, auth.ErrConfig) {
			t.Fatalf("error %v, want auth.ErrConfig", err)
		}
	})
}

func TestClientKeyFromEnvReadsOnlyTheEnvironment(t *testing.T) {
	authGuestOrSkip(t)
	t.Run("both variables set", func(t *testing.T) {
		cleanEnv(t, newProfile(t, loggedIn("profile-token")))
		t.Setenv(envClientID, testClientID)
		t.Setenv(envClientKey, testClientKey)
		resolved, err := resolveCreds(t, oidcWith(ClientKeyFromEnv()))
		if err != nil {
			t.Fatal(err)
		}
		if resolved.ClientID != testClientID || string(guest.KeyBytes(resolved.ClientKey)) != testClientKey {
			t.Error("the client key is not the environment's")
		}
	})
	t.Run("unset: not the profile's key", func(t *testing.T) {
		dir := newProfile(t, loggedIn("profile-token"))
		addWorkspaceKey(t, dir, testCRNWorkspace, namedClientID)
		cleanEnv(t, dir)
		t.Setenv(envClientID, testClientID)
		resolved, err := resolveCreds(t, oidcWith(ClientKeyFromEnv()))
		if err == nil {
			t.Fatalf("resolved with ClientID %q, want no key", resolved.ClientID)
		}
		if !errors.Is(err, ErrNoCredentials) || !strings.Contains(err.Error(), envClientKey) {
			t.Errorf("error %v, want ErrNoCredentials naming %s", err, envClientKey)
		}
		if strings.Contains(err.Error(), "stash auth login") {
			t.Errorf("error %q suggests the profile, which this source does not read", err)
		}
	})
	t.Run("set but empty", func(t *testing.T) {
		cleanEnv(t, newProfile(t, loggedIn("profile-token")))
		setUnusableKeyVariables(t)
		_, err := resolveCreds(t, oidcWith(ClientKeyFromEnv()))
		if !errors.Is(err, ErrEncoding) {
			t.Fatalf("error %v, want ErrEncoding", err)
		}
		if strings.Contains(err.Error(), testClientKey[:16]) {
			t.Fatalf("the error carries key material: %q", err)
		}
	})
}

func TestClientKeyFromValuesReadsNothingElse(t *testing.T) {
	authGuestOrSkip(t)
	dir := newProfile(t, loggedIn("profile-token"))
	addWorkspaceKey(t, dir, testCRNWorkspace, namedClientID)
	cleanEnv(t, dir)
	setUnusableKeyVariables(t)
	key := NewClientKey([]byte(testClientKey))
	creds := oidcWith(ClientKeyFromValues(testClientID, key))
	resolved, err := resolveCreds(t, creds)
	if err != nil {
		t.Fatalf("resolve: %v (the environment was read)", err)
	}
	if resolved.ClientID != testClientID || resolved.ClientKey != key {
		t.Errorf("ClientID = %q, want the values given", resolved.ClientID)
	}
	// The key is for one client.
	if _, err := resolveCreds(t, creds); !errors.Is(err, ErrCredentialsConsumed) {
		t.Fatalf("a second resolve: %v, want ErrCredentialsConsumed", err)
	}
}

// Only a source that reads the profile has the profile directory mounted
// in the credential guest.
func TestOnlyAProfileSourceMountsTheProfile(t *testing.T) {
	for _, tc := range []struct {
		key  ClientKeySource
		want bool
	}{
		{ClientKeyFromEnv(), false},
		{ClientKeyFromValues(testClientID, NewClientKey([]byte(testClientKey))), false},
		{ClientKeyFromProfile(testCRN), true},
		{OIDCFederation(testCRN, nil).clientKey(), true},
	} {
		if got := tc.key.usesProfile(); got != tc.want {
			t.Errorf("%v: usesProfile = %t, want %t", tc.key, got, tc.want)
		}
	}
}

// A source built wrong is refused host-side, before any guest is read, and
// key material it holds is wiped all the same.
func TestOIDCFederationClientKeyIsCheckedBeforeResolving(t *testing.T) {
	var nilCreds *OIDCFederationCredentials
	wiped := NewClientKey([]byte(testClientKey))
	consumed := ClientKeyFromValues(testClientID, NewClientKey([]byte(testClientKey)))
	consumed.(*valuesKeySource).discard()
	for _, tc := range []struct {
		name  string
		creds Credentials
		want  error
		names string
	}{
		{"a nil source", oidcWith(nil), ErrEncoding, "nil ClientKeySource"},
		{"a profile source with no CRN", oidcWith(ClientKeyFromProfile(" ")), ErrEncoding, "workspace CRN"},
		{"values with no client id", oidcWith(ClientKeyFromValues("", wiped)), ErrEncoding, "client id"},
		{"values with no key", oidcWith(ClientKeyFromValues(testClientID, nil)), ErrEncoding, "client key"},
		{"values already consumed", oidcWith(consumed), ErrCredentialsConsumed, "consumed"},
		{"nil credentials", nilCreds, ErrEncoding, "nil *OIDCFederationCredentials"},
		{"nil credentials given a source", nilCreds.WithClientKey(ClientKeyFromEnv()), ErrEncoding, "nil *OIDCFederationCredentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t, t.TempDir())
			_, err := NewClient(context.Background(), WithCredentials(tc.creds))
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("NewClient: %v, want %v naming %q", err, tc.want, tc.names)
			}
		})
	}
	if !wiped.IsZero() {
		t.Error("the key of a refused ClientKeyFromValues still holds material")
	}
}

// Credentials with a ClientKeyFromValues source are consumed as
// NewCredentials are: by a refused config, by a later WithCredentials, and
// by a resolve that fails before the key is read.
func TestClientKeyFromValuesIsConsumedOnEveryPath(t *testing.T) {
	t.Run("a refused config, then a retry", func(t *testing.T) {
		cleanEnv(t, t.TempDir())
		key := NewClientKey([]byte(testClientKey))
		creds := oidcWith(ClientKeyFromValues(testClientID, key))
		if _, err := NewClient(context.Background(), WithCredentials(creds), WithKeysetCacheSize(-1)); !errors.Is(err, ErrEncoding) {
			t.Fatalf("NewClient: %v, want ErrEncoding", err)
		}
		if !key.IsZero() {
			t.Error("the key was handed back live with the refused config")
		}
		if _, err := NewClient(context.Background(), WithCredentials(creds)); !errors.Is(err, ErrCredentialsConsumed) {
			t.Fatalf("retry: %v, want ErrCredentialsConsumed", err)
		}
	})
	t.Run("replaced by a later WithCredentials", func(t *testing.T) {
		cleanEnv(t, t.TempDir())
		key := NewClientKey([]byte(testClientKey))
		replaced := oidcWith(ClientKeyFromValues(testClientID, key))
		_, _ = NewClient(context.Background(), WithCredentials(replaced), WithCredentials(AutoCredentials()), WithKeysetCacheSize(-1))
		if !key.IsZero() {
			t.Error("the replaced credentials' key still holds material")
		}
	})
	t.Run("the same source passed twice is the client's", func(t *testing.T) {
		source := ClientKeyFromValues(testClientID, NewClientKey([]byte(testClientKey)))
		a, b := oidcWith(source), oidcWith(source)
		if !sameExplicit(a, b) || !sameExplicit(a, a) {
			t.Error("credentials sharing one ClientKeyFromValues source are not the same key")
		}
		if sameExplicit(a, oidcWith(ClientKeyFromValues(testClientID, NewClientKey([]byte(testClientKey))))) {
			t.Error("two sources compare as one")
		}
	})
	t.Run("a strategy that fails", func(t *testing.T) {
		authGuestOrSkip(t)
		cleanEnv(t, t.TempDir())
		key := NewClientKey([]byte(testClientKey))
		provider := auth.OIDCProviderFunc(func(context.Context) (string, error) { return "idp-token", nil })
		// No CRN: the strategy is refused before the key is read.
		creds := OIDCFederation("", provider).WithClientKey(ClientKeyFromValues(testClientID, key))
		if _, err := resolveCreds(t, creds); !errors.Is(err, auth.ErrConfig) {
			t.Fatalf("resolve: %v, want auth.ErrConfig", err)
		}
		if !key.IsZero() {
			t.Error("the key still holds material after the strategy failed")
		}
	})
}

// OIDCFederation with a key the program loaded makes a client: the token is
// the federated one, the key is the one given, and NewClient wipes it.
func TestOIDCFederationWithClientKeyFromValuesMakesAClient(t *testing.T) {
	guestOrSkip(t)
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	cts := newAuthServer(t)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	key := NewClientKey([]byte(testClientKey))
	_, err := NewClient(context.Background(),
		WithCredentials(oidcWith(ClientKeyFromValues(testClientID, key))),
		withZeroKMSURL(stub.URL),
	)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized from the stub", err)
	}
	if len(stub.requests) != 1 || stub.requests[0].auth != "Bearer "+cts.jwt {
		t.Fatalf("ZeroKMS requests = %+v, want one bearing the federated token", stub.requests)
	}
	if !key.IsZero() {
		t.Error("NewClient did not wipe the key")
	}
}

func TestClientKeySourcesPrintNoKey(t *testing.T) {
	material := testClientKey[:16]
	for _, v := range []any{
		ClientKeyFromEnv(),
		ClientKeyFromProfile(testCRN),
		ClientKeyFromValues(testClientID, NewClientKey([]byte(testClientKey))),
		oidcWith(ClientKeyFromValues(testClientID, NewClientKey([]byte(testClientKey)))),
		oidcWith(ClientKeyFromProfile(testCRN)),
		OIDCFederation(testCRN, nil),
	} {
		for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, material) {
				t.Errorf("%s: %q carries key material", verb, out)
			}
		}
	}
	if out := fmt.Sprint(oidcWith(ClientKeyFromValues(testClientID, nil))); out != "encrypt.OIDCFederation{crn: "+testCRN+", client_key: encrypt.ClientKeyFromValues{client_id: "+testClientID+"}}" {
		t.Errorf("OIDCFederation with a key source prints %q", out)
	}
}

func ExampleOIDCFederationCredentials_WithClientKey() {
	// A configuration loader fills this from CS_WORKSPACE_CRN,
	// CS_CLIENT_ID and CS_CLIENT_KEY. Here the values are written out
	// instead.
	type Config struct {
		WorkspaceCRN string `env:"CS_WORKSPACE_CRN,required"`
		ClientID     string `env:"CS_CLIENT_ID,required"`
		ClientKey    Secret `env:"CS_CLIENT_KEY,required"`
	}
	cfg := Config{
		WorkspaceCRN: "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY",
		ClientID:     "6a70bd18-99ac-4650-b104-37eec3a15b09",
		ClientKey:    "...", // not a real key: NewClient refuses it
	}

	// The identity provider returns the JWT of the user the request is
	// for. Get it from your identity provider's SDK, or from the request.
	provider := auth.OIDCProviderFunc(func(ctx context.Context) (string, error) {
		return "header.payload.signature", nil
	})

	// The tokens come from federation. The client key is the one the
	// program loaded: NewClient reads neither the environment nor the
	// profile for it.
	creds := OIDCFederation(cfg.WorkspaceCRN, provider).
		WithClientKey(ClientKeyFromValues(cfg.ClientID, NewClientKey([]byte(cfg.ClientKey))))
	fmt.Println(creds)

	// Run NewClient while your program handles a request: it asks the
	// provider for that request's user. Client.Close releases the
	// federation strategy.
	client, err := NewClient(context.Background(), WithCredentials(creds))
	if err == nil {
		err = client.Close()
	}
	fmt.Println(err != nil)
	// Output:
	// encrypt.OIDCFederation{crn: crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY, client_key: encrypt.ClientKeyFromValues{client_id: 6a70bd18-99ac-4650-b104-37eec3a15b09}}
	// true
}
