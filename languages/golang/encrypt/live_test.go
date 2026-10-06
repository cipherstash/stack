package encrypt_test

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Round trips through real ZeroKMS, through the generated API. See
// live_internal_test.go for the variables that enable them.

var livePeople = []testusers.User{
	{ID: 1, Age: 34, Email: "alice@example.com", Notes: "likes cats", Internal: "never stored"},
	{ID: 2, Age: 29, Email: "bob@example.com", Notes: "likes dogs"},
}

func TestLiveRecordsAndTerms(t *testing.T) {
	c := encrypt.LiveClient(t)
	ctx := t.Context()
	cipher := c.DefaultKeyset()

	encrypt.ResetSends(c)
	encrypted, err := testusers.Encrypt(ctx, cipher, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	if n := encrypt.Sends(c); n != 1 {
		t.Errorf("Encrypt made %d ZeroKMS calls for %d rows, want 1", n, len(livePeople))
	}
	if len(encrypted) != 2 || len(encrypted[0].Age.Equality) != 32 || encrypted[0].Email.Match == nil || encrypted[0].Age.Ore == nil || encrypted[0].ID != 1 {
		t.Fatalf("encrypted = %+v", encrypted)
	}

	probe, err := testusers.Fields.Age.Equality(ctx, cipher, 34)
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Equal(encrypted[0].Age.Equality) {
		t.Error("probe does not equal the stored equality term")
	}
	if probe.Equal(encrypted[1].Age.Equality) {
		t.Error("probe equals another value's term")
	}

	want := append([]testusers.User(nil), livePeople...)
	want[0].Internal = "" // left out: never stored
	encrypt.ResetSends(c)
	back, err := testusers.Decrypt(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if n := encrypt.Sends(c); n != 1 {
		t.Errorf("Decrypt made %d ZeroKMS calls, want 1", n)
	}
	if !reflect.DeepEqual(back, want) {
		t.Fatalf("decrypted %+v, want %+v", back, want)
	}
	// The client opens too, under whichever keyset sealed each row.
	if back, err := testusers.Decrypt(ctx, c, encrypted[1:]); err != nil || back[0].Email != "bob@example.com" {
		t.Fatalf("Decrypt through the client: %v %+v", err, back)
	}

	// A context extension is part of the identity: the write, the query
	// and the read all go through the extended cipher.
	tenant7, tenant8 := cipher.Extend(uint64(7)), cipher.Extend(uint64(8))
	ext, err := testusers.Encrypt(ctx, tenant7, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, cipher, ext); !errors.Is(err, encrypt.ErrForbidden) && !errors.Is(err, encrypt.ErrAuthentication) {
		t.Fatalf("extended record opened without its extension: %v", err)
	}
	if _, err := testusers.Decrypt(ctx, tenant7, ext); err != nil {
		t.Fatalf("extended record with its extension: %v", err)
	}
	other, err := testusers.Encrypt(ctx, tenant8, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := testusers.Fields.Email.Equality(ctx, tenant7, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.Equal(ext[1].Email.Equality) {
		t.Error("tenant probe does not equal the term written under the same extension")
	}
	if scoped.Equal(other[1].Email.Equality) || scoped.Equal(encrypted[1].Email.Equality) {
		t.Error("tenant probe equals another tenant's or the unextended term")
	}
}

func TestLiveForeignKeysetIsRefusedBeforeRetrieval(t *testing.T) {
	c := encrypt.LiveClient(t)
	ctx := t.Context()
	other := os.Getenv("STACK_ENCRYPT_TEST_OTHER_KEYSET")
	if other == "" {
		t.Skip("STACK_ENCRYPT_TEST_OTHER_KEYSET not set")
	}
	encrypted, err := testusers.EncryptDocument(ctx, c.Keyset(encrypt.KeysetName(other)), []testusers.Document{{Title: "tenant b", Body: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	encrypt.ResetSends(c)
	if _, err := testusers.DecryptDocument(ctx, c.DefaultKeyset(), encrypted); !errors.Is(err, encrypt.ErrForeignKeyset) {
		t.Fatalf("default cipher opened another keyset's row: %v", err)
	}
	if n := encrypt.Sends(c); n != 0 {
		t.Errorf("a foreign row cost %d ZeroKMS calls before refusal", n)
	}
	if docs, err := testusers.DecryptDocument(ctx, c, encrypted); err != nil || docs[0].Title != "tenant b" {
		t.Fatalf("client decrypt of the other keyset: %v %+v", err, docs)
	}
}

// The hermetic residency test (TestPlaintextDoesNotRemainInGuestMemory)
// runs on every pull request; this is the same check across a real ZeroKMS
// request, where the guest also stages the service's responses — wrapped
// data keys — and must wipe those too.
func TestPlaintextDoesNotRemainInGuestMemoryAfterLiveRoundTrip(t *testing.T) {
	c := encrypt.LiveClient(t)
	cipher := c.DefaultKeyset()
	const plaintext = "residency-probe-4111-b1c2d3e4f5"
	probe := testusers.User{ID: 1, Age: 34, Email: "probe@example.com", Notes: plaintext}
	encrypted, err := testusers.Encrypt(t.Context(), cipher, []testusers.User{probe})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if n := bytes.Count(encrypt.GuestMemory(t, c), []byte(plaintext)); n != 0 {
		t.Fatalf("plaintext found %d times in guest memory after Encrypt", n)
	}
	// After Decrypt one copy remains; see the hermetic
	// TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt for the cause.
	if _, err := testusers.Decrypt(t.Context(), cipher, encrypted); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
}
