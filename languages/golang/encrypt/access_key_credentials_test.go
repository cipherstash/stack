package encrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

func testAccessKeyCredentials() AccessKeyCredentials {
	return AccessKeyCredentials{
		ClientID:        testClientID,
		ClientKey:       testClientKey,
		ClientAccessKey: testAccessKey,
		WorkspaceCRN:    testCRN,
	}
}

// The tags are what a configuration loader reads, so each one must name the
// variable AutoCredentials reads for the same value, in the comma form both
// go-envconfig and caarlos0/env parse.
func TestAccessKeyCredentialsEnvTags(t *testing.T) {
	want := map[string]string{
		"ClientID":        envClientID + ",required",
		"ClientKey":       envClientKey + ",required",
		"ClientAccessKey": envAccessKey + ",required",
		"WorkspaceCRN":    envWorkspaceCRN + ",required",
	}
	typ := reflect.TypeFor[AccessKeyCredentials]()
	if typ.NumField() != len(want) {
		t.Fatalf("AccessKeyCredentials has %d fields, want %d", typ.NumField(), len(want))
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		if got := field.Tag.Get("env"); got != want[field.Name] {
			t.Errorf("%s: env tag %q, want %q", field.Name, got, want[field.Name])
		}
	}
}

// An empty field is refused before the credential guest is opened, every
// empty field is named, and the error carries neither key.
func TestAccessKeyCredentialsRefusesEmptyFields(t *testing.T) {
	creds := testAccessKeyCredentials()
	creds.ClientID = ""
	creds.WorkspaceCRN = ""
	_, err := creds.resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("resolve: %v, want ErrEncoding", err)
	}
	for _, name := range []string{"ClientID (CS_CLIENT_ID)", "WorkspaceCRN (CS_WORKSPACE_CRN)"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name %s: %q", name, err)
		}
	}
	for _, name := range []string{"ClientKey", "ClientAccessKey"} {
		if strings.Contains(err.Error(), name) {
			t.Errorf("the error names %s, which is set: %q", name, err)
		}
	}
	for _, leak := range []string{testClientKey[:16], testAccessKey} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the error carries key material: %q", err)
		}
	}
}

// The struct's values are the credentials, whatever the environment and
// the developer profile hold: neither is a fallback, nor an override.
func TestAccessKeyCredentialsIgnoreTheEnvironmentAndTheProfile(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, newProfile(t, loggedIn("profile-token")))
	cts := newAuthServer(t)
	t.Setenv(envClientID, profileClientID)
	t.Setenv(envClientKey, "decoy")
	t.Setenv(envAccessKey, "CSAKdecoy.decoy")
	t.Setenv(envWorkspaceCRN, "crn:ap-southeast-2.aws:DECOYDECOYDECOY0")
	resolved, err := testAccessKeyCredentials().resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolved.Close() })
	if resolved.ClientID != testClientID || string(guest.KeyBytes(resolved.ClientKey)) != testClientKey {
		t.Error("the client key is not the struct's")
	}
	if got := token(t, resolved); got != cts.jwt || cts.calls.Load() != 1 {
		t.Errorf("Token = %q after %d exchanges, want the access key's", got, cts.calls.Load())
	}
	if resolved.MemoryLockError == nil {
		t.Error("MemoryLockError is not set: the credential guest's lock state is not reported")
	}
}

// With no profile directory at all, the CI and container shape.
func TestAccessKeyCredentialsWithNoProfile(t *testing.T) {
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	cts := newAuthServer(t)
	resolved, err := testAccessKeyCredentials().resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	if got := token(t, resolved); got != cts.jwt {
		t.Errorf("Token = %q, want the access key's", got)
	}
	// Close releases the strategy and its guest.
	if err := resolved.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := resolved.Token.Token(context.Background()); !errors.Is(err, auth.ErrState) {
		t.Fatalf("Token after Close: %v, want ErrState", err)
	}
}

// NewClient sends the exchanged token to ZeroKMS, and releases the
// credentials when it fails.
func TestNewClientWithAccessKeyCredentials(t *testing.T) {
	guestOrSkip(t)
	authGuestOrSkip(t)
	cleanEnv(t, filepath.Join(t.TempDir(), "absent"))
	cts := newAuthServer(t)
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	t.Setenv("CS_ZEROKMS_HOST", stub.URL)
	var released *resolvedCredentials
	creds := credentialsFunc(func(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error) {
		r, err := testAccessKeyCredentials().resolve(ctx, opts)
		released = r
		return r, err
	})
	_, err := NewClient(context.Background(), WithCredentials(creds))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("NewClient: %v, want ErrUnauthorized from the stub", err)
	}
	if len(stub.requests) != 1 || stub.requests[0].auth != "Bearer "+cts.jwt {
		t.Fatalf("requests = %+v, want one bearing the exchanged token", stub.requests)
	}
	if _, err := released.Token.Token(context.Background()); !errors.Is(err, auth.ErrState) {
		t.Fatalf("the token source after a failed NewClient: %v, want ErrState", err)
	}
}

// NewClient refuses an empty field without asking ZeroKMS.
func TestNewClientRefusesEmptyAccessKeyCredentials(t *testing.T) {
	guestOrSkip(t)
	stub := newStub(t, http.StatusOK, "", "")
	t.Setenv("CS_ZEROKMS_HOST", stub.URL)
	_, err := NewClient(context.Background(), WithCredentials(AccessKeyCredentials{}))
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("NewClient: %v, want ErrEncoding", err)
	}
	if len(stub.requests) != 0 {
		t.Fatalf("ZeroKMS was asked %d times", len(stub.requests))
	}
}

// Neither key is printed or logged, under any verb a program might use.
func TestAccessKeyCredentialsPrintNoKey(t *testing.T) {
	creds := testAccessKeyCredentials()
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("config", "creds", creds)
	outputs := []string{logged.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, creds), fmt.Sprintf(verb, &creds))
	}
	for _, out := range outputs {
		if strings.Contains(out, testClientKey[:16]) || strings.Contains(out, testAccessKey) {
			t.Errorf("printed a key: %q", out)
		}
		if !strings.Contains(out, testClientID) {
			t.Errorf("does not name the client id: %q", out)
		}
	}
}
