package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// A field sealed into an EQL type, through generated code, over the
// deterministic test build of the guest WITH the EQL types (ADR-0007,
// amended 2026-10-06): the guest runs TextEq's own plan and returns the
// finished value, Go stores it as it is. The other build refuses the same
// declaration before any value crosses.

func deterministicEQLClient(t *testing.T) *encrypt.Client {
	t.Helper()
	c, err := encrypt.NewDeterministicEQLClient(context.Background(), testSeed)
	if errors.Is(err, encrypt.ErrDeterministicEQLGuestNotBuilt) || errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var contacts = []testusers.Contact{
	{ID: 1, Email: "bob@example.com", Notes: "likes cats"},
	{ID: 2, Email: "alice@example.com", Notes: "likes dogs"},
	{ID: 3, Email: "bob@example.com"},
}

// eqlEnvelope is the EQL v3 envelope of a TextEq value, as PostgreSQL's
// public.eql_v3_text_eq domain checks it.
type eqlEnvelope struct {
	V  int `json:"v"`
	I  struct{ T, C string }
	C  string `json:"c"`
	HM string `json:"hm"`
}

func decodeEnvelope(t *testing.T, value []byte) eqlEnvelope {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		t.Fatalf("the EQL value is not JSON: %v: %s", err, value)
	}
	var e eqlEnvelope
	if err := json.Unmarshal(value, &e); err != nil {
		t.Fatal(err)
	}
	var id struct {
		T string `json:"t"`
		C string `json:"c"`
	}
	if err := json.Unmarshal(raw["i"], &id); err != nil {
		t.Fatal(err)
	}
	e.I.T, e.I.C = id.T, id.C
	if len(raw) != 4 {
		t.Fatalf("a TextEq value has exactly v, i, c and hm: %s", value)
	}
	return e
}

func TestTextEqFieldSealsToTheEQLEnvelope(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.EncryptContact(ctx, cipher, contacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != len(contacts) {
		t.Fatalf("%d rows for %d values", len(encrypted), len(contacts))
	}
	for i, e := range encrypted {
		if e.ID != contacts[i].ID {
			t.Errorf("row %d: passthrough id %d, want %d", i, e.ID, contacts[i].ID)
		}
		env := decodeEnvelope(t, e.Email)
		if env.V != 3 {
			t.Errorf("row %d: v = %d, want 3", i, env.V)
		}
		if env.I.T != "users" || env.I.C != "email" {
			t.Errorf("row %d: i = %+v, want users/email", i, env.I)
		}
		if !strings.HasPrefix(env.C, "stack-encrypt:1:") {
			t.Errorf("row %d: c does not carry the stack-encrypt producer marker: %q", i, env.C)
		}
		if len(env.HM) != 64 {
			t.Errorf("row %d: hm is %d hex characters, want 64", i, len(env.HM))
		}
		if len(e.Notes.Ciphertext) == 0 {
			t.Errorf("row %d: notes not sealed", i)
		}
	}
	// Equal plaintexts share the equality term and nothing else.
	first, third := decodeEnvelope(t, encrypted[0].Email), decodeEnvelope(t, encrypted[2].Email)
	if first.HM != third.HM {
		t.Error("equal emails must share hm")
	}
	if first.C == third.C {
		t.Error("each write seals under a fresh key")
	}
	if first.HM == decodeEnvelope(t, encrypted[1].Email).HM {
		t.Error("different emails must not share hm")
	}

	// The value is what the driver stores and reads back.
	v, err := encrypted[0].Email.Value()
	if err != nil || v.(string) != string(encrypted[0].Email) {
		t.Fatalf("Value = %v, %v", v, err)
	}
	var scanned eql.TextEq
	if err := scanned.Scan([]byte(encrypted[0].Email)); err != nil || !bytes.Equal(scanned, encrypted[0].Email) {
		t.Fatalf("Scan = %s, %v", scanned, err)
	}

	// Opens through the cipher and through the client.
	for _, d := range []encrypt.Decrypter{cipher, c} {
		decrypted, err := testusers.DecryptContact(ctx, d, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		for i := range contacts {
			if decrypted[i] != contacts[i] {
				t.Errorf("row %d: %+v, want %+v", i, decrypted[i], contacts[i])
			}
		}
	}
}

func TestTextEqQueryMatchesTheStoredValueAndTheRustFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "eql", "tests", "encryption", "fixtures", "text_eq_query.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Table, Column, Plaintext, Query string
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Table != "users" || fixture.Column != "email" {
		t.Fatalf("the fixture's column changed: %+v", fixture)
	}

	query, err := testusers.ContactFields.Email.Query(ctx, cipher, fixture.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Byte for byte what eql-bindings' own dispatch derived under the same
	// index key: the Go field runs TextEq's plan and no other.
	if string(query) != fixture.Query {
		t.Fatalf("Query = %s\nwant    %s", query, fixture.Query)
	}
	stored, err := testusers.ContactFields.Email.Encrypt(ctx, cipher, fixture.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		HM string `json:"hm"`
	}
	if err := json.Unmarshal(query, &probe); err != nil {
		t.Fatal(err)
	}
	if env := decodeEnvelope(t, stored); env.HM != probe.HM {
		t.Fatalf("the query's hm %s does not match the stored %s", probe.HM, env.HM)
	}
	if other, _ := testusers.ContactFields.Email.Query(ctx, cipher, "Bob@example.com"); string(other) == fixture.Query {
		t.Fatal("no case folding: a different plaintext has a different term")
	}
}

// A stored EQL value changed before it is opened: moved to another column,
// or replaced with bytes that are not a TextEq. Neither opens, and the
// second is refused as malformed input before any key is retrieved.
func TestATamperedEQLValueDoesNotOpen(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	moved, err := testusers.EncryptContact(ctx, cipher, contacts[:1])
	if err != nil {
		t.Fatal(err)
	}
	original := moved[0].Email
	moved[0].Email = eql.TextEq(bytes.Replace(original, []byte(`"c":"email"`), []byte(`"c":"notes"`), 1))
	if bytes.Equal(moved[0].Email, original) {
		t.Fatal("the stored identifier was not where the test expected it")
	}
	if _, err := testusers.DecryptContact(ctx, cipher, moved); err == nil {
		t.Fatal("an EQL value moved to another column opened")
	}

	junk, err := testusers.EncryptContact(ctx, cipher, contacts[:1])
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]eql.TextEq{
		"an empty object": eql.TextEq(`{}`),
		"not JSON":        eql.TextEq(`not json`),
		"a query value":   eql.TextEq(`{"v":3,"i":{"t":"users","c":"email"},"hm":"00"}`),
	} {
		junk[0].Email = value
		if _, err := testusers.DecryptContact(ctx, cipher, junk); !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: Decrypt = %v, want ErrEncoding", name, err)
		}
	}

	// One flipped byte in the ciphertext inside the value: authenticated,
	// so it does not open; the untouched value still does.
	flipped, err := testusers.EncryptContact(ctx, cipher, contacts[:1])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(flipped[0].Email, &doc); err != nil {
		t.Fatal(err)
	}
	var ct string
	if err := json.Unmarshal(doc["c"], &ct); err != nil {
		t.Fatal(err)
	}
	last := []byte(ct)
	if last[len(last)-2] == 'A' {
		last[len(last)-2] = 'B'
	} else {
		last[len(last)-2] = 'A'
	}
	doc["c"], _ = json.Marshal(string(last))
	tampered, _ := json.Marshal(doc)
	flipped[0].Email = eql.TextEq(tampered)
	if _, err := testusers.DecryptContact(ctx, cipher, flipped); err == nil {
		t.Fatal("a tampered ciphertext opened")
	}
	if _, err := testusers.DecryptContact(ctx, cipher, contactsSealed(t, ctx, cipher)); err != nil {
		t.Fatalf("the untouched value no longer opens: %v", err)
	}
}

func contactsSealed(t *testing.T, ctx context.Context, cipher *encrypt.Cipher) []testusers.EncryptedContact {
	t.Helper()
	sealed, err := testusers.EncryptContact(ctx, cipher, contacts[:1])
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestTextEqIsRefusedByTheBuildWithoutEQLTypes(t *testing.T) {
	ctx := context.Background()
	plain, err := encrypt.PlainGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	checker, err := encrypt.NewCheckerOver(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = checker.Close() }()
	targets, err := checker.Targets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("the build without EQL types lists %d targets", len(targets))
	}
	plan := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "email", Kind: record.String, Target: "TextEq"}}}
	if err := checker.Check(ctx, plan); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("Check = %v, want ErrEncoding", err)
	}

	// The build with them lists the catalog and runs the plan.
	withEQL, err := encrypt.EmbeddedGuest()
	if err != nil {
		t.Fatal(err)
	}
	eqlChecker, err := encrypt.NewCheckerOver(ctx, withEQL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eqlChecker.Close() }()
	targets, err = eqlChecker.Targets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, target := range targets {
		found = found || target.Name == "TextEq"
	}
	if !found {
		t.Fatalf("TextEq is not among the %d targets", len(targets))
	}
	if err := eqlChecker.Check(ctx, plan); err != nil {
		t.Fatalf("the eql build refuses TextEq: %v", err)
	}
	for _, name := range []string{"TextOrdOre", "Nope"} {
		refused := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "email", Kind: record.String, Target: name}}}
		if err := eqlChecker.Check(ctx, refused); !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: Check = %v, want ErrEncoding", name, err)
		}
	}
	// A declared type other than TextEq's plaintext, and an extended plan.
	wrongKind := &record.Plan{Context: []string{"users"}, Fields: []record.Field{{Name: "email", Kind: record.UInt64, Target: "TextEq"}}}
	if err := eqlChecker.Check(ctx, wrongKind); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("a uint64 TextEq field: Check = %v, want ErrEncoding", err)
	}
	extended := &record.Plan{Context: []string{"users"}, Extension: []any{uint64(7)}, Fields: []record.Field{{Name: "email", Kind: record.String, Target: "TextEq"}}}
	if err := eqlChecker.Check(ctx, extended); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("an extended plan with a target field: Check = %v, want ErrEncoding", err)
	}
}

func TestExtendedCipherRefusesATextEqField(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	tenant := c.DefaultKeyset().Extend(uint64(7))
	_, err := testusers.EncryptContact(ctx, tenant, contacts[:1])
	if !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("an extended cipher sealed a TextEq field: %v", err)
	}
}
