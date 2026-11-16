package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
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

// NewClient refuses credentials that are wrong as they were built before it
// loads the guest, so the refusal names the field even where no guest is
// built: an empty struct, the same as a pointer, and a nil pointer, which
// would otherwise panic inside the Credentials interface.
func TestNewClientRefusesAccessKeyCredentialsHostSide(t *testing.T) {
	stub := newStub(t, http.StatusOK, "", "")
	t.Setenv("CS_ZEROKMS_HOST", stub.URL)
	for name, creds := range map[string]Credentials{
		"empty":       AccessKeyCredentials{},
		"empty, *":    &AccessKeyCredentials{},
		"nil pointer": (*AccessKeyCredentials)(nil),
	} {
		_, err := NewClient(context.Background(), WithCredentials(creds), withGuest([]byte("not wasm")))
		if !errors.Is(err, ErrEncoding) || !strings.Contains(err.Error(), "AccessKeyCredentials") {
			t.Errorf("%s: NewClient: %v, want ErrEncoding naming AccessKeyCredentials", name, err)
		}
	}
	if len(stub.requests) != 0 {
		t.Fatalf("ZeroKMS was asked %d times", len(stub.requests))
	}
}

// Encoding the credentials redacts the keys, so decoding them again gives
// the text [redacted]. NewClient refuses that and says why, rather than
// sending it to CTS and blaming the access key.
func TestNewClientRefusesRedactedAccessKeyCredentials(t *testing.T) {
	encoded, err := json.Marshal(testAccessKeyCredentials())
	if err != nil {
		t.Fatal(err)
	}
	var decoded AccessKeyCredentials
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(context.Background(), WithCredentials(decoded), withGuest([]byte("not wasm")))
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("NewClient: %v, want ErrEncoding", err)
	}
	for _, want := range []string{"ClientKey (CS_CLIENT_KEY)", "ClientAccessKey (CS_CLIENT_ACCESS_KEY)", "encoded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %q", want, err)
		}
	}
}

// Neither key is printed or logged under any verb, by slog, or by
// encoding/json: not on its own, not as a named field of a configuration
// struct, and not embedded in one. Embedding hides none of the outer
// struct's own fields.
func TestAccessKeyCredentialsPrintNoKey(t *testing.T) {
	creds := testAccessKeyCredentials()
	type named struct {
		Port        int
		CipherStash AccessKeyCredentials
	}
	type embedded struct {
		Port int
		AccessKeyCredentials
	}
	values := map[string]any{
		"on its own": creds,
		"a pointer":  &creds,
		"named":      named{Port: 8080, CipherStash: creds},
		"embedded":   embedded{Port: 8080, AccessKeyCredentials: creds},
	}
	for name, v := range values {
		var outputs []string
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%x"} {
			outputs = append(outputs, fmt.Sprintf(verb, v))
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(encoded))
		if name != "a pointer" { // xml has no name for an unnamed pointer's element
			encoded, err = xml.Marshal(v)
			if err != nil {
				t.Fatalf("%s: xml: %v", name, err)
			}
			outputs = append(outputs, string(encoded))
		}
		for _, handler := range []func(*bytes.Buffer) slog.Handler{
			func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var logged bytes.Buffer
			slog.New(handler(&logged)).Info("config", "config", v)
			outputs = append(outputs, logged.String())
		}
		for _, out := range outputs {
			if strings.Contains(out, testClientKey[:16]) || strings.Contains(out, testAccessKey) {
				t.Errorf("%s: printed a key: %q", name, out)
			}
		}
		// %+v names every field, so a field hidden by a promoted method
		// would be missing here.
		if out := fmt.Sprintf("%+v", v); !strings.Contains(out, "ClientID:"+testClientID) ||
			(name == "named" || name == "embedded") && !strings.Contains(out, "Port:8080") {
			t.Errorf("%s: %%+v hides a field: %q", name, out)
		}
	}
	// A Secret on its own: logged, and through the methods a Stringer or
	// GoStringer API calls.
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("key", "key", creds.ClientKey)
	for _, out := range []string{logged.String(), creds.ClientKey.String(), creds.ClientKey.GoString()} {
		if strings.Contains(out, testClientKey[:16]) || !strings.Contains(out, redacted) {
			t.Errorf("a Secret printed: %q", out)
		}
	}
}

// A field holding only whitespace is as unset as an empty one.
func TestAccessKeyCredentialsRefusesBlankFields(t *testing.T) {
	creds := testAccessKeyCredentials()
	creds.ClientAccessKey = " \t\n"
	_, err := creds.resolve(context.Background(), resolveOptions{Transport: http.DefaultTransport})
	if !errors.Is(err, ErrEncoding) || !strings.Contains(err.Error(), "ClientAccessKey (CS_CLIENT_ACCESS_KEY)") {
		t.Fatalf("resolve: %v, want ErrEncoding naming ClientAccessKey", err)
	}
}

func ExampleAccessKeyCredentials() {
	// A configuration loader such as go-envconfig or caarlos0/env fills
	// this from CS_CLIENT_ID, CS_CLIENT_KEY, CS_CLIENT_ACCESS_KEY and
	// CS_WORKSPACE_CRN. Here the values are written out instead.
	type Config struct {
		Port        int `env:"PORT"`
		CipherStash AccessKeyCredentials
	}
	cfg := Config{
		Port: 8080,
		CipherStash: AccessKeyCredentials{
			ClientID:        "6a70bd18-99ac-4650-b104-37eec3a15b09",
			ClientKey:       "...", // not a real key: NewClient refuses it
			ClientAccessKey: "CSAK...",
			WorkspaceCRN:    "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY",
		},
	}
	// The keys never print.
	fmt.Printf("%+v\n", cfg)

	// NewClient owns the token exchange, and Close releases it.
	ctx := context.Background()
	client, err := NewClient(ctx, WithCredentials(cfg.CipherStash))
	if err == nil {
		err = client.Close()
	}
	fmt.Println(err != nil)
	// Output:
	// {Port:8080 CipherStash:{ClientID:6a70bd18-99ac-4650-b104-37eec3a15b09 ClientKey:[redacted] ClientAccessKey:[redacted] WorkspaceCRN:crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY}}
	// true
}
