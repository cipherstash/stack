package encrypt_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Everything the generator accepts round-trips: one sealed field of every
// scalar kind, defined types among them, passthrough fields of types the FFI
// codec cannot carry, and an opaque struct with a field of every type JSON
// carries. Hermetic, over the deterministic guest.

func TestPassthroughKeepsEveryGoType(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	when := time.Date(2026, 10, 6, 1, 2, 3, 4, time.FixedZone("AEDT", 11*3600))
	accounts := []testusers.Account{
		{ID: 1, CreatedAt: when, DeletedAt: sql.NullTime{Time: when.Add(time.Hour), Valid: true}, Email: "alice@example.com"},
		{ID: 2, CreatedAt: when.UTC(), Email: "bob@example.com"},
	}
	encrypted, err := testusers.EncryptAccount(ctx, cipher, accounts)
	if err != nil {
		t.Fatal(err)
	}
	if !encrypted[0].CreatedAt.Equal(when) || encrypted[0].DeletedAt != accounts[0].DeletedAt || encrypted[1].ID != 2 {
		t.Fatalf("passthrough fields: %+v", encrypted)
	}
	back, err := testusers.DecryptAccount(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, accounts) {
		t.Fatalf("DecryptAccount = %+v, want %+v", back, accounts)
	}
}

func TestEverySealedKindRoundTrips(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	seven := 7
	when := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	in := []testusers.Kinds{{
		S: "alice", E: "alice@example.com", Bo: true,
		I8: -8, I16: -16, I32: -32, I: -64, I64: -1 << 40,
		U8: 8, U16: 16, U32: 32, U: 64, U64: 1 << 40,
		F32: 1.5, F64: -2.25,
		By: []byte{1, 2, 3}, Bl: testusers.Blob{4, 5}, Sc: -3, St: "active", D: 90 * time.Second,
		P: &seven, M: map[string]string{"k": "v"}, T: when, N: sql.NullTime{Time: when, Valid: true},
		In: testusers.Inner{Name: "in", N: 1}, Sk: []testusers.Inner{{Name: "a", N: 2}},
		A: "any", Er: errKept,
	}, {
		// A and Er are nil interfaces: a nil interface asserts to no type,
		// and the passthrough still comes back as nil.
		S: "bob", E: "bob@example.com", I8: 127, I16: 32767, I32: 1<<31 - 1, I: 1 << 30, I64: 1<<63 - 1,
		U8: 255, U16: 65535, U32: 1<<32 - 1, U: 1 << 30, U64: 1<<64 - 1,
		F32: -0.5, F64: 1e300, By: []byte{}, Bl: testusers.Blob{}, Sc: 32767, St: "x", D: -time.Minute,
		M: map[string]string{}, Sk: []testusers.Inner{},
	}}
	encrypted, err := testusers.EncryptKinds(ctx, cipher, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range encrypted {
		if len(e.E.Equality) != 32 || len(e.E.Match) == 0 || len(e.E.Ore) == 0 || len(e.Sc.Ore) == 0 || len(e.F64.Ore) == 0 || len(e.U64.Ope) == 0 {
			t.Fatalf("terms missing: %+v", e)
		}
	}
	back, err := testusers.DecryptKinds(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("DecryptKinds =\n%+v\nwant\n%+v", back, in)
	}
	// A defined type's field entry takes and derives at the defined type.
	term, err := testusers.KindsFields.E.Equality(ctx, cipher, testusers.Email("alice@example.com"))
	if err != nil || !term.Equal(encrypted[0].E.Equality) {
		t.Fatalf("defined-type probe: %v", err)
	}
	one, err := testusers.KindsFields.Sc.Encrypt(ctx, cipher, -3)
	if err != nil || len(one.Ciphertext) == 0 {
		t.Fatalf("Score field: %v", err)
	}
	if probe, err := testusers.KindsFields.St.Equality(ctx, cipher, "active"); err != nil || !probe.Equal(encrypted[0].St.Equality) {
		t.Fatalf("Status probe: %v", err)
	}
}

// A model in separate columns: each term is in its own column, and the rows
// decrypt back to the input. The reviewer's test.
func TestModelRowsRoundTrip(t *testing.T) {
	c := deterministicClient(t)
	cipher := c.DefaultKeyset()
	rows, err := testusers.EncryptRows(t.Context(), cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := testusers.Fields.Email.Equality(t.Context(), cipher, people[1].Email)
	if err != nil || !probe.Equal(rows[1].EmailEq) || probe.Equal(rows[0].EmailEq) {
		t.Fatalf("EmailEq does not hold the email's equality term: %v", err)
	}
	ageProbe, err := testusers.Fields.Age.Ore(t.Context(), cipher, people[1].Age)
	if err != nil || ageProbe.Compare(rows[1].AgeOre) != 0 || !rows[1].AgeOre.Less(rows[0].AgeOre) {
		t.Fatalf("AgeOre does not hold the age's ORE term: %v", err)
	}
	match, err := testusers.Fields.Email.Match(t.Context(), cipher, people[1].Email)
	if err != nil || !bytes.Equal(match, rows[1].EmailMatch) || len(rows[1].Notes) == 0 || rows[1].ID != people[1].ID {
		t.Fatalf("the other columns: %v %+v", err, rows[1])
	}
	want := append([]testusers.User(nil), people...)
	want[0].Internal = ""
	back, err := testusers.DecryptRows(t.Context(), c, rows)
	if err != nil || !reflect.DeepEqual(back, want) {
		t.Fatalf("DecryptRows = %+v, %v", back, err)
	}
	// A row whose columns were swapped does not open as the input.
	rows[0].Age, rows[0].Notes = rows[0].Notes, rows[0].Age
	if _, err := testusers.DecryptRows(t.Context(), c, rows[:1]); err == nil {
		t.Fatal("swapped columns opened")
	}
}

func TestEveryOpaqueFieldTypeRoundTrips(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	hello := "hello"
	when := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	in := []testusers.Everything{{
		S: "s", E: "e@example.com", Bo: true, I8: -1, I: 42, U64: 1 << 40, F32: 0.25, F64: 9.75,
		By: []byte("bytes"), Bl: testusers.Blob("blob"), Sc: -7,
		Tags: []string{"a", "b"}, Ints: []int{1, -2}, F32s: []float32{1.5, -0.25}, St: "active", D: time.Hour, Emails: []testusers.Email{"x@y"}, Counts: map[string]int{"a": 1}, Labels: map[string]string{"k": "v"}, ByKey: map[int]string{3: "three"},
		In: testusers.Inner{Name: "in", N: 5}, Ins: []testusers.Inner{{Name: "i", N: 6}}, P: &hello, PI: &testusers.Inner{Name: "pi", N: 7},
		T: when, N: sql.NullTime{Time: when, Valid: true}, Nested: [][]byte{{1}, {2, 3}}, Arr: [2]uint8{9, 8},
	}, {
		// Zero values, with the slices and maps nil: JSON null comes back as nil.
	}}
	encrypted, err := testusers.EncryptEverything(ctx, cipher, in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := testusers.DecryptEverything(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("DecryptEverything =\n%+v\nwant\n%+v", back, in)
	}
}

var errKept = errors.New("kept as it is")

// An index-only field stores its terms and no ciphertext: Decrypt opens the
// sealed fields and leaves it at its zero value.
func TestIndexOnlyFieldsDecryptToTheirZeroValue(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	in := []testusers.Lookup{{ID: 1, Email: "alice@example.com", Score: 30, Code: "gold"}, {ID: 2, Email: "bob@example.com", Score: 10, Code: "grey"}}
	encrypted, err := testusers.EncryptLookup(ctx, cipher, in)
	if err != nil {
		t.Fatal(err)
	}
	if !encrypted[1].Score.Ore.Less(encrypted[0].Score.Ore) || len(encrypted[0].Code.Equality) == 0 {
		t.Fatalf("index-only terms: %+v", encrypted)
	}
	probe, err := testusers.LookupFields.Code.Equality(ctx, cipher, "gold")
	if err != nil || !probe.Equal(encrypted[0].Code.Equality) {
		t.Fatalf("Code probe: %v", err)
	}
	back, err := testusers.DecryptLookup(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	want := []testusers.Lookup{{ID: 1, Email: "alice@example.com"}, {ID: 2, Email: "bob@example.com"}}
	if !reflect.DeepEqual(back, want) {
		t.Fatalf("DecryptLookup = %+v, want %+v", back, want)
	}
}

// A nil []byte in a sealed field comes back as an empty, non-nil slice: the
// engine carries bytes, not their absence. cmd/stashgen/README.md says so.
func TestANilSealedByteSliceComesBackEmpty(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	encrypted, err := testusers.EncryptKinds(ctx, c.DefaultKeyset(), []testusers.Kinds{{S: "carol", E: "carol@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	back, err := testusers.DecryptKinds(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if back[0].By == nil || len(back[0].By) != 0 || back[0].Bl == nil || len(back[0].Bl) != 0 {
		t.Fatalf("By = %#v, Bl = %#v; want empty and non-nil", back[0].By, back[0].Bl)
	}
}

// An empty batch, nil or zero-length, encrypts and decrypts to nothing.
func TestAnEmptyBatchRoundTrips(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	for _, in := range [][]testusers.User{nil, {}} {
		encrypted, err := testusers.Encrypt(ctx, c.DefaultKeyset(), in)
		if err != nil || len(encrypted) != 0 {
			t.Fatalf("Encrypt(%#v) = %v, %v", in, encrypted, err)
		}
		back, err := testusers.Decrypt(ctx, c, encrypted)
		if err != nil || len(back) != 0 {
			t.Fatalf("Decrypt(%#v) = %v, %v", encrypted, back, err)
		}
	}
}

// encoding/json refuses NaN and the infinities, so an opaque struct holding
// one is an ErrEncoding that names the value, not an unclassified error.
func TestANonFiniteFloatInAnOpaqueStructIsErrEncoding(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	for _, v := range []testusers.Everything{{F64: math.NaN()}, {F32: float32(math.Inf(1))}} {
		_, err := testusers.EncryptEverything(ctx, c.DefaultKeyset(), []testusers.Everything{v})
		if !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "value 0") {
			t.Fatalf("err = %v, want ErrEncoding naming value 0", err)
		}
	}
}

// A nil *Cipher or *Client held in a Decrypter is not a nil interface, so
// Decrypt reaches Open, which returns an error instead of panicking.
func TestDecryptThroughANilCipherOrClientIsAnError(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	encrypted, err := testusers.Encrypt(ctx, c.DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	var cipher *encrypt.Cipher
	var client *encrypt.Client
	for _, d := range []encrypt.Decrypter{cipher, client} {
		if _, err := testusers.Decrypt(ctx, d, encrypted); !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("Decrypt through %T(nil): %v", d, err)
		}
	}
}

// Identity keeps a renamed field's context: data sealed under the old name
// opens under the new one when the new one declares the old as its
// identity, and does not open without it.
func TestARenamedFieldOpensUnderItsIdentity(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	type value struct{ Email string }
	type sealed struct{ Email encrypt.Ciphertext }
	codec := func(name string, decl gensupport.Declaration) *gensupport.Codec[value, sealed] {
		return gensupport.New(gensupport.Generated[value, sealed]{
			TypeName:    "value",
			Declaration: decl,
			Source:      func(v value) gensupport.Values { return gensupport.Values{name: v.Email} },
			Seal:        func(rec gensupport.Record) (sealed, error) { return sealed{rec[name].Ciphertext}, nil },
			Open:        func(e sealed) gensupport.Record { return gensupport.Record{name: {Ciphertext: e.Email}} },
			Value: func(_ sealed, vals gensupport.Values) (value, error) {
				s, err := gensupport.Get[string](vals, name)
				return value{s}, err
			},
		})
	}
	before := codec("email", gensupport.Declare("users").Encrypt("email", gensupport.String))
	renamed := codec("mail", gensupport.Declare("users").Encrypt("mail", gensupport.String).Identity("mail", "email"))
	unkept := codec("mail", gensupport.Declare("users").Encrypt("mail", gensupport.String))

	encrypted, err := before.Encrypt(ctx, c.DefaultKeyset(), []value{{"alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	back, err := renamed.Decrypt(ctx, c, encrypted)
	if err != nil || back[0].Email != "alice@example.com" {
		t.Fatalf("renamed with its identity: %v, %v", back, err)
	}
	if _, err := unkept.Decrypt(ctx, c, encrypted); err == nil {
		t.Fatal("renamed without its identity opened the old data")
	}
}
