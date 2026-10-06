package encrypt_test

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

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
		By: []byte{1, 2, 3}, Bl: testusers.Blob{4, 5}, Sc: -3,
		P: &seven, M: map[string]string{"k": "v"}, T: when, N: sql.NullTime{Time: when, Valid: true},
		In: testusers.Inner{Name: "in", N: 1}, Sk: []testusers.Inner{{Name: "a", N: 2}},
	}, {
		S: "bob", E: "bob@example.com", I8: 127, I16: 32767, I32: 1<<31 - 1, I: 1 << 30, I64: 1<<63 - 1,
		U8: 255, U16: 65535, U32: 1<<32 - 1, U: 1 << 30, U64: 1<<64 - 1,
		F32: -0.5, F64: 1e300, By: []byte{}, Bl: testusers.Blob{}, Sc: 32767,
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
		Tags: []string{"a", "b"}, Emails: []testusers.Email{"x@y"}, Counts: map[string]int{"a": 1}, Labels: map[string]string{"k": "v"}, ByKey: map[int]string{3: "three"},
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
