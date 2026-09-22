package stackencrypt

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Round trips through real ZeroKMS key material. Run by the phase 5
// harness (`mise run test:integration:wasi-go`), which boots zerokms-server
// and exports the four variables below; skipped otherwise.

func liveClient(t *testing.T) *Client {
	t.Helper()
	guestOrSkip(t)
	clientID, clientKey := os.Getenv("STACK_ENCRYPT_TEST_CLIENT_ID"), os.Getenv("STACK_ENCRYPT_TEST_CLIENT_KEY")
	token, url := os.Getenv("STACK_ENCRYPT_TEST_ACCESS_TOKEN"), os.Getenv("STACK_ENCRYPT_TEST_ZEROKMS_URL")
	if clientID == "" || clientKey == "" || token == "" {
		t.Skip("STACK_ENCRYPT_TEST_{CLIENT_ID,CLIENT_KEY,ACCESS_TOKEN} not set")
	}
	c, err := NewClient(t.Context(), Config{
		ClientID: clientID, ClientKey: NewClientKey([]byte(clientKey)), ZeroKMSURL: url, Token: StaticToken(token),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type liveUser struct {
	ID    int64  `stash:"-"`
	Age   uint32 `stash:"context=users/age,index=eq;ore"`
	Email string `stash:"context=users/email,index=eq;match"`
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

	probe, err := cipher.Term(ctx, uint32(34), MustContext("users/age"), Equality)
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
		FieldPlan{Field: "Age", Context: "users/age", Terms: []TermKind{Equality, Ore}},
		FieldPlan{Field: "Email", Context: "users/email", Terms: []TermKind{Equality, Match}},
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
	other, err := NewPlan(FieldPlan{Field: "Email", Name: "email", Context: "users/email"})
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
