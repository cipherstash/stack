package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// A Go integer of another width stored as an integer EQL type (ADR-0002) is
// sealed at the type's width: it opens back into its own Go type, its
// equality term is the one an int32 or int64 field stores for the same value
// under the same column, and a value of a wider type that does not fit is
// refused with ErrEncoding.
func TestIntegersOfOtherWidthsSealAtTheirEQLTypesWidth(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	in := testusers.Widened{Visits: 200, Balance: -5, Age: 34, Rank: math.MaxUint32, Count: math.MaxInt32}
	encrypted, err := testusers.EncryptWidened(ctx, cipher, []testusers.Widened{in})
	if err != nil {
		t.Fatal(err)
	}
	back, err := testusers.DecryptWidened(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if back[0] != in {
		t.Fatalf("DecryptWidened = %+v, want %+v", back[0], in)
	}

	same, err := testusers.EncryptProfile(ctx, cipher, []testusers.Profile{{Age: 34, Rank: math.MaxUint32, Name: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	hm := func(value []byte) string {
		t.Helper()
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(value, &raw); err != nil {
			t.Fatalf("the EQL value is not JSON: %v", err)
		}
		return string(raw["hm"])
	}
	if got, want := hm(encrypted[0].Age), hm(same[0].Age); got == "" || got != want {
		t.Errorf("an int16 into IntegerEq stores hm %s, an int32 %s", got, want)
	}
	if got, want := hm(encrypted[0].Rank), hm(same[0].Rank); got == "" || got != want {
		t.Errorf("a uint32 into BigintEq stores hm %s, an int64 %s", got, want)
	}

	// A query converts its operand as a write does, so it finds what the
	// write stored: the same query as an int32 or int64 field's.
	age, err := testusers.WidenedFields.Age.Eq(ctx, cipher, 34)
	if err != nil {
		t.Fatal(err)
	}
	wantAge, err := testusers.ProfileFields.Age.Eq(ctx, cipher, 34)
	if err != nil {
		t.Fatal(err)
	}
	if string(age) != string(wantAge) {
		t.Errorf("an int16 IntegerEq query = %s, an int32's %s", age, wantAge)
	}
	rank, err := testusers.WidenedFields.Rank.Eq(ctx, cipher, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	wantRank, err := testusers.ProfileFields.Rank.Eq(ctx, cipher, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	if string(rank) != string(wantRank) {
		t.Errorf("a uint32 BigintEq query = %s, an int64's %s", rank, wantRank)
	}
	if _, err := testusers.WidenedFields.Count.Eq(ctx, cipher, math.MaxInt32+1); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("an int64 query outside IntegerEq's range: %v, want ErrEncoding", err)
	}

	for _, count := range []int64{math.MaxInt32 + 1, math.MinInt32 - 1} {
		_, err := testusers.EncryptWidened(ctx, cipher, []testusers.Widened{{Count: count}})
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("an int64 outside IntegerEq's range: %v, want ErrEncoding", err)
		}
	}
}
