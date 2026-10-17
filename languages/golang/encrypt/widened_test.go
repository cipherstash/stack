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

	for _, count := range []int64{math.MaxInt32 + 1, math.MinInt32 - 1} {
		_, err := testusers.EncryptWidened(ctx, cipher, []testusers.Widened{{Count: count}})
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("an int64 outside IntegerEq's range: %v, want ErrEncoding", err)
		}
	}
}
