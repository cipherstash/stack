package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Optional fields, declared over pointers (#1298), through generated code
// over the deterministic guest build with the EQL types. A sealed null is as
// long as a value and the stored field never shows it; a SQL null stores
// nothing. Both decrypt to nil.

func ptr[T any](v T) *T { return &v }

// hmOf is the equality term an EQL value or query holds.
func hmOf(t *testing.T, value []byte) string {
	t.Helper()
	var envelope struct {
		HM string `json:"hm"`
	}
	if err := json.Unmarshal(value, &envelope); err != nil || envelope.HM == "" {
		t.Fatalf("the EQL value has no hm: %v: %s", err, value)
	}
	return envelope.HM
}

// cOf is the length of the `c` an EQL value stores.
func cOf(t *testing.T, value []byte) int {
	t.Helper()
	var envelope struct {
		C string `json:"c"`
	}
	if err := json.Unmarshal(value, &envelope); err != nil {
		t.Fatalf("the EQL value is not JSON: %v", err)
	}
	if envelope.C == "" {
		t.Fatalf("the EQL value has no c: %s", value)
	}
	return len(envelope.C)
}

func TestOptionalFieldsStoreNilAsTheirTagsSay(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	dob, born := encrypt.Date{Year: 1990, Month: 5, Day: 17}, encrypt.Date{Year: 1991, Month: 6, Day: 1}
	people := []testusers.Person{
		{ID: 1, DOB: &dob, Born: &born, Joined: &born, Age: ptr(int32(34)), Score: ptr(int64(7)), Nick: ptr("al")},
		{ID: 2},
		{ID: 3},
	}
	sealed, err := testusers.EncryptPerson(ctx, cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	present, absent := sealed[0], sealed[1]

	// A sealed null: a value whose ciphertext is as long as a date's, or
	// an int32's, so the column does not show which rows are absent.
	if len(absent.DOB) == 0 || cOf(t, absent.DOB) != cOf(t, present.DOB) {
		t.Fatalf("a nil DOB is sealed as long as a date: %s, beside %s", absent.DOB, present.DOB)
	}
	if len(absent.Age.Ciphertext) != len(present.Age.Ciphertext) {
		t.Fatalf("a nil Age is sealed as long as an int32: %d bytes, beside %d", len(absent.Age.Ciphertext), len(present.Age.Ciphertext))
	}
	if cOf(t, absent.Born) != cOf(t, present.Born) {
		t.Fatalf("a nil Born is sealed as long as a date")
	}
	// Beside equality, a sealed null stores the term every nil shares, and
	// EqNull is its query (#1298).
	other := sealed[2]
	if hmOf(t, absent.Born) != hmOf(t, other.Born) || hmOf(t, absent.Born) == hmOf(t, present.Born) {
		t.Fatal("every nil Born shares one term, and no date has it")
	}
	if !bytes.Equal(absent.Age.Equality, other.Age.Equality) || bytes.Equal(absent.Age.Equality, present.Age.Equality) {
		t.Fatal("every nil Age shares one term, and no int32 has it")
	}
	bornNull, err := testusers.PersonFields.Born.EqNull(ctx, cipher)
	if err != nil || hmOf(t, bornNull) != hmOf(t, absent.Born) {
		t.Fatalf("Born.EqNull is the query of the stored nils: %v", err)
	}
	ageNull, err := testusers.PersonFields.Age.EqNull(ctx, cipher)
	if err != nil || !bytes.Equal(ageNull, absent.Age.Equality) {
		t.Fatalf("Age.EqNull is the query of the stored nils: %v", err)
	}
	// One column set to nil: EncryptNull seals what a whole record's nil
	// seals, as long as a value, with the term every nil shares.
	dobNil, err := testusers.PersonFields.DOB.EncryptNull(ctx, cipher)
	if err != nil || cOf(t, dobNil) != cOf(t, present.DOB) {
		t.Fatalf("DOB.EncryptNull is as long as a date: %v", err)
	}
	bornNil, err := testusers.PersonFields.Born.EncryptNull(ctx, cipher)
	if err != nil || hmOf(t, bornNil) != hmOf(t, absent.Born) {
		t.Fatalf("Born.EncryptNull stores the nils' term: %v", err)
	}
	ageNil, err := testusers.PersonFields.Age.EncryptNull(ctx, cipher)
	if err != nil || len(ageNil.Ciphertext) != len(present.Age.Ciphertext) || !bytes.Equal(ageNil.Equality, absent.Age.Equality) {
		t.Fatalf("Age.EncryptNull is as long as an int32 and stores the nils' term: %v", err)
	}
	updated, err := testusers.DecryptPerson(ctx, cipher, []testusers.EncryptedPerson{{ID: 4, DOB: dobNil, Born: bornNil, Age: ageNil}})
	if err != nil || updated[0].DOB != nil || updated[0].Born != nil || updated[0].Age != nil {
		t.Fatalf("what EncryptNull seals decrypts to nil: %v, %+v", err, updated)
	}

	// A SQL null: nothing stored, so the column holds NULL.
	if absent.Joined != nil || absent.Score != nil || absent.Nick != nil {
		t.Fatalf("a nil null=sql field stores nothing: %+v", absent)
	}
	if present.Joined == nil || present.Score == nil || present.Nick == nil {
		t.Fatalf("a present null=sql field is stored: %+v", present)
	}
	var stored eql.Date
	if err := stored.Scan([]byte(absent.DOB)); err != nil {
		t.Fatalf("a sealed null is a value the column scans: %v", err)
	}

	opened, err := testusers.DecryptPerson(ctx, cipher, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got := opened[1]; got.ID != 2 || got.DOB != nil || got.Born != nil || got.Joined != nil || got.Age != nil || got.Score != nil || got.Nick != nil {
		t.Fatalf("every nil decrypts to nil: %+v", got)
	}
	got := opened[0]
	if got.DOB == nil || *got.DOB != dob || got.Born == nil || *got.Born != born || got.Joined == nil || *got.Joined != born || got.Age == nil || *got.Age != 34 ||
		got.Score == nil || *got.Score != 7 || got.Nick == nil || *got.Nick != "al" {
		t.Fatalf("every value decrypts as it was: %+v", got)
	}

	// A field that is not a pointer has no nil to give: the stored null is
	// a decrypt error, not a zero date.
	_, err = testusers.DecryptBirthday(ctx, cipher, []testusers.EncryptedBirthday{{DOB: absent.DOB}})
	if err == nil {
		t.Fatal("a sealed null decrypted into encrypt.Date, which has no nil")
	}
	birthdays, err := testusers.DecryptBirthday(ctx, cipher, []testusers.EncryptedBirthday{{DOB: present.DOB}})
	if err != nil || birthdays[0].DOB != dob {
		t.Fatalf("a present date reads into either: %v, %+v", err, birthdays)
	}
}
