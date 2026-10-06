package encrypt

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Round trips through real ZeroKMS key material run when these variables
// are set (CI's `live` job exports them; locally a gitignored mise.local.toml
// can), and each test is skipped unless its own are:
//
//   - STACK_ENCRYPT_TEST_CLIENT_ID, STACK_ENCRYPT_TEST_CLIENT_KEY: the
//     seeded client (every live test);
//   - STACK_ENCRYPT_TEST_CLIENT_ACCESS_KEY, STACK_ENCRYPT_TEST_WORKSPACE_CRN:
//     an access key and its workspace, exchanged for a token (every live
//     test) — by an auth access-key strategy given to NewCredentials
//     (liveClient), and by AutoCredentials from the environment
//     (TestLiveAutoCredentialsFromTheEnvironment). There is no raw-token
//     variable: the client takes tokens only from auth strategies;
//   - STACK_ENCRYPT_TEST_ZEROKMS_URL (optional): the ZeroKMS endpoint, else
//     the token's services claim;
//   - STACK_ENCRYPT_TEST_CTS_HOST (optional): the authentication endpoint
//     the access key is exchanged at, else discovery from the workspace CRN;
//   - STACK_ENCRYPT_TEST_OTHER_KEYSET (optional): a second keyset's name.
//
// The round trips through generated code are in live_test.go (package
// encrypt_test, which can import the generated test types this package
// cannot); this file holds the client they share and the one test that
// needs the package's internals.

func liveClient(t *testing.T) *Client {
	t.Helper()
	clientID, clientKey := os.Getenv("STACK_ENCRYPT_TEST_CLIENT_ID"), os.Getenv("STACK_ENCRYPT_TEST_CLIENT_KEY")
	accessKey, crn := os.Getenv("STACK_ENCRYPT_TEST_CLIENT_ACCESS_KEY"), os.Getenv("STACK_ENCRYPT_TEST_WORKSPACE_CRN")
	url := os.Getenv("STACK_ENCRYPT_TEST_ZEROKMS_URL")
	if clientID == "" || clientKey == "" || accessKey == "" || crn == "" {
		t.Skip("STACK_ENCRYPT_TEST_{CLIENT_ID,CLIENT_KEY,CLIENT_ACCESS_KEY,WORKSPACE_CRN} not set")
	}
	guestOrSkip(t)
	authGuestOrSkip(t)
	// The explicit path: the caller opens the store and the strategy, and
	// closes them after the client (cleanups run last-registered first).
	store, err := auth.OpenWithoutProfile(t.Context())
	if err != nil {
		t.Fatalf("auth.OpenWithoutProfile: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var strategyOpts []auth.StrategyOption
	if cts := os.Getenv("STACK_ENCRYPT_TEST_CTS_HOST"); cts != "" {
		strategyOpts = append(strategyOpts, auth.WithAuthBaseURL(cts))
	}
	strategy, err := store.AccessKey(t.Context(), crn, accessKey, strategyOpts...)
	if err != nil {
		t.Fatalf("auth access-key strategy: %v", err)
	}
	t.Cleanup(func() {
		if err := strategy.Close(); err != nil {
			t.Errorf("strategy.Close: %v", err)
		}
	})
	material := []byte(clientKey)
	key := NewClientKey(material)
	// The credentials a successful NewClient resolved are released by the
	// client's Close, once: the wiring only a real load-keyset response can
	// reach. NewCredentials itself holds nothing to release — the strategy
	// is the caller's — so the spy adds a Close to count.
	var released int
	creds := credentialsFunc(func(ctx context.Context, opts resolveOptions) (*resolvedCredentials, error) {
		r, err := NewCredentials(clientID, key, strategy).resolve(ctx, opts)
		if err == nil {
			r.Close = func() error { released++; return nil }
		}
		return r, err
	})
	c, err := NewClient(t.Context(), WithCredentials(creds), withZeroKMSURL(url))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = c.Close()
		if released != 1 {
			t.Errorf("Close released the credentials %d times, want once", released)
		}
		// The client never closes the caller's strategy.
		if _, err := strategy.Token(context.Background()); err != nil {
			t.Errorf("the strategy after Client.Close: %v, want still usable", err)
		}
	})
	if released != 0 {
		t.Fatalf("a successful NewClient released the credentials %d times, want 0", released)
	}
	// The successful outcome of the consumption contract, which only a
	// real load-keyset response can reach: the key is empty and the bytes
	// it was built from are zero once the client exists.
	if !key.IsZero() {
		t.Error("the key still holds material after NewClient succeeded")
	}
	for i, b := range material {
		if b != 0 {
			t.Fatalf("byte %d of the key material was not wiped by a successful NewClient", i)
		}
	}
	return c
}

// The zero-configuration path end to end: NewClient with no options, its
// credentials from AutoCredentials, the token from a real access-key
// exchange — the CI shape of a deployment, with the variables the Rust
// client reads and no developer profile. It drives the record path directly
// because this package's tests cannot import the generated test types.
func TestLiveAutoCredentialsFromTheEnvironment(t *testing.T) {
	clientID, clientKey := os.Getenv("STACK_ENCRYPT_TEST_CLIENT_ID"), os.Getenv("STACK_ENCRYPT_TEST_CLIENT_KEY")
	accessKey, crn := os.Getenv("STACK_ENCRYPT_TEST_CLIENT_ACCESS_KEY"), os.Getenv("STACK_ENCRYPT_TEST_WORKSPACE_CRN")
	if clientID == "" || clientKey == "" || accessKey == "" || crn == "" {
		t.Skip("STACK_ENCRYPT_TEST_{CLIENT_ID,CLIENT_KEY,CLIENT_ACCESS_KEY,WORKSPACE_CRN} not set")
	}
	guestOrSkip(t)
	authGuestOrSkip(t)
	// An empty profile directory, so only the environment can answer, and
	// none of the developer's own CS_* variables.
	cleanEnv(t, t.TempDir())
	if cts := os.Getenv("STACK_ENCRYPT_TEST_CTS_HOST"); cts != "" {
		t.Setenv("CS_CTS_HOST", cts)
	} else if err := os.Unsetenv("CS_CTS_HOST"); err != nil { // cleanEnv's placeholder
		t.Fatal(err)
	}
	if url := os.Getenv("STACK_ENCRYPT_TEST_ZEROKMS_URL"); url != "" {
		t.Setenv("CS_ZEROKMS_HOST", url)
	}
	t.Setenv(envAccessKey, accessKey)
	t.Setenv(envWorkspaceCRN, crn)
	t.Setenv(envClientID, clientID)
	t.Setenv(envClientKey, clientKey)

	ctx := t.Context()
	c, err := NewClient(ctx)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	// Whether memory locks depends on the host; that it is reported, and
	// consistently, does not.
	if err := c.MemoryLockError(); err != nil && !errors.Is(err, ErrMemoryLock) {
		t.Errorf("MemoryLockError = %v, want nil or ErrMemoryLock", err)
	}
	if c.MemoryLocked() != (c.MemoryLockError() == nil) {
		t.Error("MemoryLocked disagrees with MemoryLockError")
	}

	plan := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "name", Kind: record.String, Outputs: []record.Output{record.Ciphertext}}}}
	sealed, err := c.DefaultKeyset().Seal(ctx, plan, []record.Source{{"name": "alice"}})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != 1 || len(sealed[0]["name"].Ciphertext) == 0 {
		t.Fatalf("sealed = %v", sealed)
	}
	back, err := c.Open(ctx, plan, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(back) != 1 || back[0]["name"] != "alice" {
		t.Fatalf("Open = %#v, want alice", back)
	}
}
