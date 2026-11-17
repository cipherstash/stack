package witheql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/eqlguest"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// These tests use the client as an application's tests would: through
// generated code, with no credentials and no network. testusers names an
// EQL type, so this binary links package eql and gets the test build with
// the EQL types. ../withouteql covers the other build.

var people = []testusers.User{
	{ID: 1, Age: 34, Email: "alice@example.com", Notes: "likes cats"},
	{ID: 2, Age: 29, Email: "bob@example.com", Notes: "likes dogs"},
}

func TestTheBinaryLinksTheEQLBuild(t *testing.T) {
	if !eqlguest.Linked() {
		t.Fatal("testusers names an EQL type, so package eql must be linked here")
	}
}

func TestRoundTripThroughGeneratedCode(t *testing.T) {
	client := encrypttest.NewClient(t)
	ctx := t.Context()
	cipher := client.DefaultKeyset()

	rows, err := testusers.Encrypt(ctx, cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	// The client and the cipher both take the place of a Decrypter.
	for name, d := range map[string]encrypt.Decrypter{"client": client, "cipher": cipher} {
		back, err := testusers.Decrypt(ctx, d, rows)
		if err != nil {
			t.Fatalf("through the %s: %v", name, err)
		}
		if !reflect.DeepEqual(back, people) {
			t.Fatalf("through the %s: %+v, want %+v", name, back, people)
		}
	}
	// A query term matches the stored term of the same value only.
	probe, err := testusers.Fields.Email.Eq(ctx, cipher, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Equal(rows[1].Email.Equality) || probe.Equal(rows[0].Email.Equality) {
		t.Error("the equality probe does not single out its row")
	}
}

func TestAnEQLValueAndItsQueryMatch(t *testing.T) {
	client := encrypttest.NewClient(t)
	ctx := t.Context()
	cipher := client.DefaultKeyset()

	contacts := []testusers.Contact{{ID: 1, Email: "ada@example.com", Notes: "first"}}
	rows, err := testusers.EncryptContact(ctx, cipher, contacts)
	if err != nil {
		t.Fatal(err)
	}
	query, err := testusers.ContactFields.Email.Eq(ctx, cipher, "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if hm(t, rows[0].Email) != hm(t, query) {
		t.Fatal("the query's equality term does not match the stored value's")
	}
	back, err := testusers.DecryptContact(ctx, client, rows)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, contacts) {
		t.Fatalf("%+v, want %+v", back, contacts)
	}
}

// hm reads the equality term from an EQL value or query.
func hm(t *testing.T, value []byte) string {
	t.Helper()
	var v struct {
		HM string `json:"hm"`
	}
	if err := json.Unmarshal(value, &v); err != nil || v.HM == "" {
		t.Fatalf("no hm in %s: %v", value, err)
	}
	return v.HM
}

func TestEveryKeysetExistsAndRefusesAnother(t *testing.T) {
	client := encrypttest.NewClient(t)
	ctx := t.Context()
	tenantA := client.Keyset(encrypt.KeysetName("tenant-a"))
	tenantB := client.Keyset(encrypt.KeysetName("tenant-b"))

	rows, err := testusers.Encrypt(ctx, tenantB, people)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, tenantA, rows); !errors.Is(err, encrypt.ErrForeignKeyset) {
		t.Fatalf("tenant A's cipher on tenant B's rows: %v, want ErrForeignKeyset", err)
	}
	idB, err := tenantB.KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	idA, err := tenantA.KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if idA == idB {
		t.Fatal("two keyset names resolved to one keyset")
	}
	// Selected by id, with nothing created first.
	for name, d := range map[string]encrypt.Decrypter{"client": client, "keyset by id": client.Keyset(idB)} {
		if _, err := testusers.Decrypt(ctx, d, rows); err != nil {
			t.Fatalf("through the %s: %v", name, err)
		}
	}
	// The name "default" is the default keyset.
	def, err := client.DefaultKeyset().KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	named, err := client.Keyset(encrypt.KeysetName("default")).KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if def != named {
		t.Fatalf("KeysetName(\"default\") is %v, the default keyset is %v", named, def)
	}
}

func TestAWrongContextFailsAsInProduction(t *testing.T) {
	client := encrypttest.NewClient(t)
	ctx := t.Context()
	cipher := client.DefaultKeyset()

	// A value sealed under one scope does not open under another.
	rows, err := testusers.Encrypt(ctx, cipher.Scope("tenant-7"), people)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, cipher.Scope("tenant-8"), rows); !errors.Is(err, encrypt.ErrForbidden) {
		t.Fatalf("under another scope: %v, want ErrForbidden", err)
	}

	// A row whose context field is not the cipher's is refused.
	notes := []testusers.Note{{Tenant: "tenants/acme", Text: "hello", ID: 1}}
	sealed, err := testusers.EncryptNote(ctx, cipher, notes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.DecryptNote(ctx, cipher.Context("tenants/globex"), sealed); !errors.Is(err, encrypt.ErrContextMismatch) {
		t.Fatalf("an acme row through the globex cipher: %v, want ErrContextMismatch", err)
	}
}

func TestTheDefaultSeedIsSharedAcrossClients(t *testing.T) {
	writer := encrypttest.NewClient(t)
	rows, err := testusers.Encrypt(t.Context(), writer.Keyset(encrypt.KeysetName("fixtures")), people)
	if err != nil {
		t.Fatal(err)
	}
	reader := encrypttest.NewClient(t)
	back, err := testusers.Decrypt(t.Context(), reader, rows)
	if err != nil {
		t.Fatalf("a second client with the default seed: %v", err)
	}
	if !reflect.DeepEqual(back, people) {
		t.Fatalf("%+v, want %+v", back, people)
	}
}

func TestAnotherSeedDoesNotOpenTheValues(t *testing.T) {
	writer := encrypttest.NewClient(t)
	rows, err := testusers.Encrypt(t.Context(), writer.DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	other := encrypttest.NewClient(t, encrypttest.WithSeed([32]byte{1}))
	if _, err := testusers.Decrypt(t.Context(), other, rows); !errors.Is(err, encrypt.ErrForbidden) {
		t.Fatalf("under another seed: %v, want ErrForbidden", err)
	}
	// The same seed opens them.
	same := encrypttest.NewClient(t, encrypttest.WithSeed([32]byte{1}))
	resealed, err := testusers.Encrypt(t.Context(), same.DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(t.Context(), other, resealed); err != nil {
		t.Fatalf("under the same chosen seed: %v", err)
	}
	// Search terms depend on the keyset, not the seed.
	if !bytes.Equal(rows[0].Email.Equality, resealed[0].Email.Equality) {
		t.Error("two seeds derived different search terms for one value")
	}
}

func TestTheClientIsClosedWhenTheTestEnds(t *testing.T) {
	var client *encrypt.Client
	t.Run("uses the client", func(t *testing.T) {
		client = encrypttest.NewClient(t)
		if _, err := testusers.Encrypt(t.Context(), client.DefaultKeyset(), people); err != nil {
			t.Fatal(err)
		}
	})
	_, err := testusers.Encrypt(context.Background(), client.DefaultKeyset(), people)
	if !errors.Is(err, encrypt.ErrState) {
		t.Fatalf("after the test that made it ended: %v, want ErrState", err)
	}
}
