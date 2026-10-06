package encrypt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Round trips through real ZeroKMS key material. No CI harness runs these
// yet: one that boots zerokms-server and exports the variables below is
// tracked in CIP-4024. Until then they run locally when the variables are
// set (from a gitignored mise.local.toml, say), and each test is skipped
// unless its own are:
//
//   - STACK_ENCRYPT_TEST_CLIENT_ID, STACK_ENCRYPT_TEST_CLIENT_KEY: the
//     seeded client (every live test);
//   - STACK_ENCRYPT_TEST_CLIENT_ACCESS_KEY, STACK_ENCRYPT_TEST_WORKSPACE_CRN:
//     an access key and its workspace, exchanged for a token (every live
//     test) — by a auth access-key strategy given to NewCredentials
//     (liveClient), and by AutoCredentials from the environment
//     (TestLiveAutoCredentialsFromTheEnvironment). There is no raw-token
//     variable: the client takes tokens only from auth strategies;
//   - STACK_ENCRYPT_TEST_ZEROKMS_URL (optional): the ZeroKMS endpoint, else
//     the token's services claim;
//   - STACK_ENCRYPT_TEST_CTS_HOST (optional): the authentication endpoint
//     the access key is exchanged at, else discovery from the workspace CRN;
//   - STACK_ENCRYPT_TEST_OTHER_KEYSET (optional): a second keyset's name.

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

type liveUser struct {
	ID    int64  `stash:"-"`
	Age   uint32 `stash:"label=users/age,index=eq;ore"`
	Email string `stash:"label=users/email,index=eq;match"`
}

func TestLiveValueRoundTrip(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()
	cipher := c.DefaultKeyset()
	aad := []byte("users/v1")
	in := map[string]any{"name": "alice", "age": uint32(34), "note": vcvalue.Plain{V: "clear"}}

	c.transport.sends.Store(0)
	ct, err := cipher.Encrypt(ctx, in, aad)
	if err != nil {
		t.Fatal(err)
	}
	if n := c.transport.sends.Load(); n != 1 {
		t.Errorf("encrypt made %d ZeroKMS calls, want 1", n)
	}
	fields := ct.(map[string]any)
	if _, ok := fields["name"].(Sealed); !ok {
		t.Fatalf("name sealed as %T", fields["name"])
	}
	if fields["note"] != (vcvalue.Plain{V: "clear"}) {
		t.Fatalf("passthrough came back as %v", fields["note"])
	}

	for name, open := range map[string]func() (any, error){
		"bound":  func() (any, error) { return cipher.Decrypt(ctx, ct, aad) },
		"client": func() (any, error) { return c.Decrypt(ctx, ct, aad) },
	} {
		pt, err := open()
		if err != nil {
			t.Fatalf("%s decrypt: %v", name, err)
		}
		want := vcvalue.Object{{Key: "age", Value: uint32(34)}, {Key: "name", Value: "alice"}, {Key: "note", Value: vcvalue.Plain{V: "clear"}}}
		if !reflect.DeepEqual(pt, want) {
			t.Fatalf("%s decrypt = %#v", name, pt)
		}
	}
	if _, err := cipher.Decrypt(ctx, ct, []byte("wrong")); err == nil {
		t.Fatal("wrong AAD decrypted")
	}
	// The default keyset's id is what the leaves carry: the bound cipher of
	// that id opens them too.
	defID, err := cipher.KeysetID(ctx)
	if err != nil {
		t.Fatalf("resolve the default keyset: %v", err)
	}
	if _, err := c.Keyset(defID).Decrypt(ctx, ct, aad); err != nil {
		t.Fatalf("decrypt under the default keyset by id: %v", err)
	}
}

func TestLiveRecordsAndTerms(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()
	cipher := c.DefaultKeyset()
	users := []liveUser{{1, 34, "alice@example.com"}, {2, 29, "bob@example.com"}}

	c.transport.sends.Store(0)
	records, err := cipher.EncryptRecords(ctx, users)
	if err != nil {
		t.Fatal(err)
	}
	if n := c.transport.sends.Load(); n != 1 {
		t.Errorf("EncryptRecords made %d ZeroKMS calls for %d rows, want 1", n, len(users))
	}
	if len(records) != 2 || len(records[0]["Age"].Equality) != 32 || records[0]["Email"].Match == nil || records[0]["Age"].Ore == nil {
		t.Fatalf("records = %+v", records)
	}

	probe, err := cipher.Term(ctx, uint32(34), label(t, "users/age").Context(), Equality)
	if err != nil {
		t.Fatal(err)
	}
	if !probe.(EqualityTerm).Equal(records[0]["Age"].Equality) {
		t.Error("probe does not equal the stored equality term")
	}
	if probe.(EqualityTerm).Equal(records[1]["Age"].Equality) {
		t.Error("probe equals another value's term")
	}

	var back []liveUser
	if err := cipher.DecryptRecords(ctx, records, &back); err != nil {
		t.Fatal(err)
	}
	for i := range users {
		users[i].ID = 0 // not part of the record
	}
	if !reflect.DeepEqual(back, users) {
		t.Fatalf("decrypted %+v, want %+v", back, users)
	}
	var one liveUser
	if err := c.DecryptRecord(ctx, records[1], &one); err != nil || one.Email != "bob@example.com" {
		t.Fatalf("DecryptRecord: %v %+v", err, one)
	}

	// A context extension is part of the identity.
	ext, err := cipher.EncryptRecords(ctx, users, ExtendContext(uint64(7)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cipher.DecryptRecords(ctx, ext, &back); !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrAuthentication) {
		t.Fatalf("extended record opened without its extension: %v", err)
	}
	if err := cipher.DecryptRecords(ctx, ext, &back, ExtendContext(uint64(7))); err != nil {
		t.Fatalf("extended record with its extension: %v", err)
	}

	// A probe takes the same option, and matches only the rows written
	// under it: not another tenant's, and not the unextended ones.
	tenant7, tenant8 := ExtendContext(uint64(7)), ExtendContext(uint64(8))
	other, err := cipher.EncryptRecords(ctx, users, tenant8)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := cipher.Term(ctx, "bob@example.com", label(t, "users/email").Context(), Equality, tenant7)
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.(EqualityTerm).Equal(ext[1]["Email"].Equality) {
		t.Error("tenant probe does not equal the term written under the same extension")
	}
	if scoped.(EqualityTerm).Equal(other[1]["Email"].Equality) {
		t.Error("tenant probe equals another tenant's term")
	}
	if scoped.(EqualityTerm).Equal(records[1]["Email"].Equality) {
		t.Error("tenant probe equals the unextended term")
	}
	unscoped, err := cipher.Term(ctx, "bob@example.com", label(t, "users/email").Context(), Equality)
	if err != nil {
		t.Fatal(err)
	}
	if unscoped.(EqualityTerm).Equal(ext[1]["Email"].Equality) {
		t.Error("an unextended probe equals a tenant's term")
	}
}

// An explicit plan round-trips a struct that carries no tags, and a record
// is only readable under the plan it was written under.
func TestLiveExplicitPlanRoundTrip(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()
	cipher := c.DefaultKeyset()
	type generated struct { // no tags, as protobuf output has none
		Age   uint32
		Email string
	}
	plan, err := NewPlan(
		FieldPlan{Field: "Age", Context: label(t, "users/age").Context(), Terms: []TermKind{Equality, Ore}},
		FieldPlan{Field: "Email", Context: label(t, "users/email").Context(), Terms: []TermKind{Equality, Match}},
	)
	if err != nil {
		t.Fatal(err)
	}
	users := []generated{{34, "alice@example.com"}, {29, "bob@example.com"}}

	records, err := cipher.EncryptRecords(ctx, users, WithPlan(plan))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(records[0]["Age"].Equality) != 32 || records[0]["Email"].Match == nil {
		t.Fatalf("records = %+v", records)
	}
	var back []generated
	if err := cipher.DecryptRecords(ctx, records, &back, WithPlan(plan)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, users) {
		t.Fatalf("decrypted %+v, want %+v", back, users)
	}
	var one generated
	if err := c.DecryptRecord(ctx, records[1], &one, WithPlan(plan)); err != nil || one.Email != "bob@example.com" {
		t.Fatalf("DecryptRecord: %v %+v", err, one)
	}

	// A plan naming a field the record does not carry is refused before
	// any key is requested.
	other, err := NewPlan(FieldPlan{Field: "Email", Name: "email", Context: label(t, "users/email").Context()})
	if err != nil {
		t.Fatal(err)
	}
	c.transport.sends.Store(0)
	err = cipher.DecryptRecords(ctx, records, &back, WithPlan(other))
	if err == nil || !strings.Contains(err.Error(), `no ciphertext for field "email"`) {
		t.Fatalf("mismatched plan: %v", err)
	}
	if n := c.transport.sends.Load(); n != 0 {
		t.Errorf("mismatched plan made %d ZeroKMS calls, want 0", n)
	}
}

func TestLiveForeignKeysetIsRefusedBeforeRetrieval(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()
	other := os.Getenv("STACK_ENCRYPT_TEST_OTHER_KEYSET")
	if other == "" {
		t.Skip("STACK_ENCRYPT_TEST_OTHER_KEYSET not set")
	}
	ct, err := c.Keyset(KeysetName(other)).Encrypt(ctx, "tenant b", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.transport.sends.Store(0)
	if _, err := c.DefaultKeyset().Decrypt(ctx, ct, nil); !errors.Is(err, ErrForeignKeyset) {
		t.Fatalf("default cipher opened another keyset's leaf: %v", err)
	}
	if n := c.transport.sends.Load(); n != 0 {
		t.Errorf("a foreign leaf cost %d ZeroKMS calls before refusal", n)
	}
	if pt, err := c.Decrypt(ctx, ct, nil); err != nil || pt != "tenant b" {
		t.Fatalf("client decrypt of the other keyset: %v %v", pt, err)
	}
}

// Per-call hygiene on a real round trip: once Encrypt has returned, the
// plaintext it was given is nowhere in guest memory — the staged input was
// wiped by se_dealloc — so between calls the guest holds only the client
// key and its keyset cache.
func TestPlaintextDoesNotRemainInGuestMemoryAfterEncrypt(t *testing.T) {
	c := liveClient(t)
	ctx := t.Context()
	const plaintext = "residency-probe-4111-b1c2d3e4f5"
	if _, err := c.DefaultKeyset().Encrypt(ctx, plaintext, nil); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	mem := c.inst.module.Memory()
	view, ok := mem.Read(0, mem.Size())
	if !ok {
		t.Fatal("cannot read guest memory")
	}
	if n := bytes.Count(view, []byte(plaintext)); n != 0 {
		t.Fatalf("plaintext found %d times in guest memory after Encrypt returned", n)
	}
}

// The zero-configuration path end to end: NewClient with no options, its
// credentials from AutoCredentials, the token from a real access-key
// exchange — the CI shape of a deployment, with the variables the Rust
// client reads and no developer profile.
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

	aad := []byte("users/v1")
	ct, err := c.DefaultKeyset().Encrypt(ctx, "alice", aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, ok := ct.(Sealed); !ok {
		t.Fatalf("sealed as %T", ct)
	}
	pt, err := c.Decrypt(ctx, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "alice" {
		t.Fatalf("Decrypt = %#v, want %q", pt, "alice")
	}
}
