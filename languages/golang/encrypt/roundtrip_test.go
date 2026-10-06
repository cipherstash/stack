package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Hermetic round trips through the real guest over the deterministic-kms
// test build: every key derives from a seed, so these need no ZeroKMS and
// run wherever `mise run wasm:guest:build:deterministic` has run.

var testSeed = [32]byte([]byte("encrypt round-trip tests seed v1"))

func deterministicClient(t *testing.T) *encrypt.Client {
	t.Helper()
	c, err := encrypt.NewDeterministicClient(context.Background(), testSeed)
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) || errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var people = []testusers.User{
	{ID: 1, Age: 34, Email: "alice@example.com", Notes: "likes cats", Internal: "never stored"},
	{ID: 2, Age: 29, Email: "bob@example.com", Notes: "likes dogs"},
	{ID: 3, Age: 29, Email: "carol@example.com"},
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.Encrypt(ctx, cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != len(people) {
		t.Fatalf("%d rows for %d values", len(encrypted), len(people))
	}
	for i, e := range encrypted {
		if e.ID != people[i].ID {
			t.Errorf("row %d: passthrough id %d, want %d", i, e.ID, people[i].ID)
		}
		if len(e.Age.Ciphertext) == 0 || len(e.Age.Equality) != 32 || len(e.Age.Ore) == 0 || len(e.Email.Ciphertext) == 0 || len(e.Email.Match) == 0 || len(e.Notes.Ciphertext) == 0 {
			t.Errorf("row %d: outputs missing: %+v", i, e)
		}
	}
	// Equal plaintexts give equal terms, under one keyset and context;
	// different ones do not.
	if !encrypted[1].Age.Equality.Equal(encrypted[2].Age.Equality) || encrypted[0].Age.Equality.Equal(encrypted[1].Age.Equality) {
		t.Error("equality terms do not follow the plaintext")
	}
	if !encrypted[1].Age.Ore.Less(encrypted[0].Age.Ore) || encrypted[1].Age.Ore.Compare(encrypted[2].Age.Ore) != 0 {
		t.Error("ORE terms do not order as the plaintexts")
	}
	// Ciphertexts are fresh each time.
	if bytes.Equal(encrypted[1].Age.Ciphertext, encrypted[2].Age.Ciphertext) {
		t.Error("two rows share a ciphertext")
	}

	want := append([]testusers.User(nil), people...)
	want[0].Internal = ""
	for _, d := range []struct {
		name string
		by   encrypt.Decrypter
	}{{"cipher", cipher}, {"client", c}} {
		back, err := testusers.Decrypt(ctx, d.by, encrypted)
		if err != nil {
			t.Fatalf("Decrypt through the %s: %v", d.name, err)
		}
		if !reflect.DeepEqual(back, want) {
			t.Fatalf("Decrypt through the %s = %+v, want %+v", d.name, back, want)
		}
	}

	// One field: the Fields entry seals and probes it.
	one, err := testusers.Fields.Email.Encrypt(ctx, cipher, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !one.Equality.Equal(encrypted[1].Email.Equality) || !bytes.Equal(one.Match, encrypted[1].Email.Match) {
		t.Error("a field's own Encrypt derives other terms than the record's")
	}
	probe, err := testusers.Fields.Email.Equality(ctx, cipher, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Equal(encrypted[1].Email.Equality) || probe.Equal(encrypted[0].Email.Equality) {
		t.Error("the probe does not single out its row")
	}
	match, err := testusers.Fields.Email.Match(ctx, cipher, "bob@example.com")
	if err != nil || !bytes.Equal(match, encrypted[1].Email.Match) {
		t.Errorf("match probe: %v", err)
	}
	// A column update: one field's ciphertext opens in a row.
	encrypted[0].Email = testusers.EncryptedUserEmail(one)
	back, err := testusers.Decrypt(ctx, cipher, encrypted[:1])
	if err != nil || back[0].Email != "bob@example.com" {
		t.Fatalf("after a column update: %v %+v", err, back)
	}
}

func TestEncryptedTypesHideSealedFields(t *testing.T) {
	e := testusers.EncryptedUser{ID: 7}
	e.Email.Ciphertext = []byte("secret bytes")
	s := e.String()
	if !strings.Contains(s, "ID: 7") || strings.Contains(s, "secret") || !strings.Contains(s, "Email: [sealed]") {
		t.Fatalf("String = %q", s)
	}
}

func TestExtendIsPartOfTheIdentity(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	tenant7, tenant8 := cipher.Extend(uint64(7)), cipher.Extend(uint64(8))

	plain, err := testusers.Encrypt(ctx, cipher, people[:2])
	if err != nil {
		t.Fatal(err)
	}
	ext, err := testusers.Encrypt(ctx, tenant7, people[:2])
	if err != nil {
		t.Fatal(err)
	}
	other, err := testusers.Encrypt(ctx, tenant8, people[:2])
	if err != nil {
		t.Fatal(err)
	}
	if ext[1].Email.Equality.Equal(plain[1].Email.Equality) || ext[1].Email.Equality.Equal(other[1].Email.Equality) {
		t.Error("terms under different extensions are equal")
	}
	if _, err := testusers.Decrypt(ctx, cipher, ext); err == nil {
		t.Fatal("an extended record opened without its extension")
	}
	if _, err := testusers.Decrypt(ctx, tenant8, ext); err == nil {
		t.Fatal("an extended record opened under another extension")
	}
	back, err := testusers.Decrypt(ctx, tenant7, ext)
	if err != nil || back[1].Email != "bob@example.com" {
		t.Fatalf("with its extension: %v %+v", err, back)
	}
	// The probe takes the same cipher.
	probe, err := testusers.Fields.Email.Equality(ctx, tenant7, "bob@example.com")
	if err != nil || !probe.Equal(ext[1].Email.Equality) || probe.Equal(plain[1].Email.Equality) {
		t.Fatalf("tenant probe: %v", err)
	}
	// Extend(a, b) is Extend(a).Extend(b); a byte part is copied.
	part := []byte("eu")
	ab, err := testusers.Encrypt(ctx, cipher.Extend(uint64(7), part), people[:1])
	if err != nil {
		t.Fatal(err)
	}
	part[0] = 'X'
	ba, err := testusers.Encrypt(ctx, tenant7.Extend([]byte("eu")), people[:1])
	if err != nil {
		t.Fatal(err)
	}
	if !ab[0].Email.Equality.Equal(ba[0].Email.Equality) {
		t.Error("Extend(a, b) and Extend(a).Extend(b) derive different terms")
	}
	// A part the codec cannot carry fails the first call, as a value.
	if _, err := testusers.Encrypt(ctx, cipher.Extend(1.5), people[:1]); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("Extend(1.5): %v, want ErrEncoding", err)
	}
}

func TestOpaqueStructSealsAsOneValue(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	docs := []testusers.Document{
		{Title: "Handbook", Body: "Welcome aboard.", Tags: []string{"hr", "onboarding"}},
		{Title: "Empty"},
	}
	encrypted, err := testusers.EncryptDocument(ctx, cipher, docs)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != 2 || len(encrypted[0].Sealed) == 0 {
		t.Fatalf("encrypted = %+v", encrypted)
	}
	back, err := testusers.DecryptDocument(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if back[0].Title != "Handbook" || back[0].Body != "Welcome aboard." || !reflect.DeepEqual(back[0].Tags, []string{"hr", "onboarding"}) || back[1].Title != "Empty" {
		t.Fatalf("DecryptDocument = %+v", back)
	}
	// A document is one column: its String hides it.
	if s := encrypted[0].String(); strings.Contains(s, "Handbook") || !strings.Contains(s, "[sealed]") {
		t.Fatalf("String = %q", s)
	}
}

func TestForeignKeysetIsRefusedBeforeAnyKey(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	other := c.Keyset(encrypt.KeysetName("tenant-b"))
	encrypted, err := testusers.Encrypt(ctx, other, people[:1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, c.DefaultKeyset(), encrypted); !errors.Is(err, encrypt.ErrForeignKeyset) {
		t.Fatalf("the default cipher opened another keyset's row: %v", err)
	}
	id, err := other.KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]encrypt.Decrypter{"client": c, "the keyset by id": c.Keyset(id), "the keyset by name": other} {
		back, err := testusers.Decrypt(ctx, d, encrypted)
		if err != nil || back[0].Email != "alice@example.com" {
			t.Fatalf("%s: %v %+v", name, err, back)
		}
	}
}

func TestATamperedRecordDoesNotOpen(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	encrypted, err := testusers.Encrypt(ctx, cipher, people[:1])
	if err != nil {
		t.Fatal(err)
	}
	// A ciphertext moved under another field's label does not open: the key
	// is bound to the descriptor.
	swapped := encrypted
	swapped[0].Notes.Ciphertext = encrypted[0].Email.Ciphertext
	if _, err := testusers.Decrypt(ctx, cipher, swapped); err == nil {
		t.Fatal("a leaf opened under another field's context")
	}
	// A flipped byte does not open.
	flipped, _ := testusers.Encrypt(ctx, cipher, people[:1])
	flipped[0].Email.Ciphertext[len(flipped[0].Email.Ciphertext)-1] ^= 1
	if _, err := testusers.Decrypt(ctx, cipher, flipped); err == nil {
		t.Fatal("a tampered leaf opened")
	}
	// A record with no ciphertext for a sealed field is refused on the host.
	missing, _ := testusers.Encrypt(ctx, cipher, people[:1])
	missing[0].Age.Ciphertext = nil
	if _, err := testusers.Decrypt(ctx, cipher, missing); err == nil || !strings.Contains(err.Error(), `"age"`) {
		t.Fatalf("a missing ciphertext: %v", err)
	}
}

// A match index needs text that yields a token: the engine defines no match
// term for an empty or separator-only string, because an empty term would
// match every row, and the typed Rust path refuses it the same way. The Go
// error names the row, the field and the index. Every other zero value
// seals: a zero integer under ore and equality, an empty string with no
// match index.
func TestAMatchIndexNeedsText(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	for name, u := range map[string]testusers.User{
		"the zero value":    {},
		"an empty email":    {ID: 1, Age: 34, Notes: "x"},
		"a separator email": {ID: 1, Age: 34, Email: " \t", Notes: "x"},
	} {
		_, err := testusers.Encrypt(ctx, cipher, []testusers.User{{ID: 9, Age: 1, Email: "ok@example.com", Notes: "x"}, u})
		if !errors.Is(err, encrypt.ErrTerm) {
			t.Fatalf("%s: %v, want ErrTerm", name, err)
		}
		for _, want := range []string{`value 1`, `field "email"`, "no match term"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q does not name %s", name, err, want)
			}
		}
	}
	// The field entry says the same for one value.
	if _, err := testusers.Fields.Email.Encrypt(ctx, cipher, ""); !errors.Is(err, encrypt.ErrTerm) || !strings.Contains(err.Error(), `field "email"`) {
		t.Fatalf("Fields.Email.Encrypt(\"\"): %v", err)
	}
	if _, err := testusers.Fields.Email.Match(ctx, cipher, ""); !errors.Is(err, encrypt.ErrTerm) {
		t.Fatalf("Fields.Email.Match(\"\"): %v", err)
	}
	// Zero values the engine does seal.
	encrypted, err := testusers.Encrypt(ctx, cipher, []testusers.User{{Email: "zero@example.com"}})
	if err != nil {
		t.Fatalf("a zero age and empty notes: %v", err)
	}
	back, err := testusers.Decrypt(ctx, cipher, encrypted)
	if err != nil || back[0].Age != 0 || back[0].Notes != "" || back[0].ID != 0 {
		t.Fatalf("zero values round trip: %v %+v", err, back)
	}
}
