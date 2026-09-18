package stackencrypt

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Property tests of term ordering: random plaintexts, terms derived by the
// guest, comparison in Go. ORE is probabilistic — a wrong comparator or a
// wrong derivation still agrees with plaintext order on many pairs — so a
// fixed vector set says little; hundreds of random pairs per type say
// more. The terms come from the guest's index key, which needs a loaded
// keyset, so these run under the live harness (skipped without
// credentials) — see live_test.go.

// orderProperty checks, for random pairs of T, that the Go comparison of
// their terms agrees with the plaintext order and that a term compares
// equal to itself (derivation is deterministic).
func orderProperty[T any](t *testing.T, cipher *Cipher, kind TermKind, less func(a, b T) int) {
	t.Helper()
	ctx := context.Background()
	context := MustContext(fmt.Sprintf("prop/%s/%T", kind, *new(T)))
	term := func(v T) []byte {
		t.Helper()
		out, err := cipher.Term(ctx, v, context, kind)
		if err != nil {
			t.Fatalf("Term(%v): %v", v, err)
		}
		switch tt := out.(type) {
		case OreTerm:
			return tt
		case OpeTerm:
			return tt
		default:
			t.Fatalf("Term returned %T", out)
			return nil
		}
	}
	compare := func(a, b []byte) int {
		if kind == Ore {
			return OreTerm(a).Compare(OreTerm(b))
		}
		return OpeTerm(a).Compare(OpeTerm(b))
	}
	sign := func(n int) int {
		return cmp.Compare(n, 0)
	}
	holds := func(a, b T) bool {
		ta, tb := term(a), term(b)
		if compare(ta, ta) != 0 || compare(tb, tb) != 0 {
			t.Logf("a term does not compare equal to itself: %v", a)
			return false
		}
		if !bytes.Equal(ta, term(a)) {
			t.Logf("derivation is not deterministic for %v", a)
			return false
		}
		want, got := sign(less(a, b)), sign(compare(ta, tb))
		if got != want {
			t.Logf("%v vs %v: plaintext order %d, term order %d", a, b, want, got)
			return false
		}
		return sign(compare(tb, ta)) == -want
	}
	cfg := &quick.Config{MaxCount: 300, Rand: rand.New(rand.NewSource(int64(kind)))}
	if err := quick.Check(holds, cfg); err != nil {
		t.Fatal(err)
	}
}

// Neighbouring values are where a comparator that mishandles the last
// differing bit shows; quick's uniform generator almost never produces
// them, so they are checked explicitly alongside.
func adjacentProperty[T any](t *testing.T, cipher *Cipher, kind TermKind, values []T, less func(a, b T) int) {
	t.Helper()
	ctx := context.Background()
	context := MustContext(fmt.Sprintf("prop/%s/%T", kind, *new(T)))
	terms := make([][]byte, len(values))
	for i, v := range values {
		out, err := cipher.Term(ctx, v, context, kind)
		if err != nil {
			t.Fatalf("Term(%v): %v", v, err)
		}
		terms[i] = reflect.ValueOf(out).Bytes()
	}
	for i := range values {
		for j := range values {
			var got int
			if kind == Ore {
				got = OreTerm(terms[i]).Compare(OreTerm(terms[j]))
			} else {
				got = OpeTerm(terms[i]).Compare(OpeTerm(terms[j]))
			}
			if want := cmp.Compare(less(values[i], values[j]), 0); got != want {
				t.Errorf("%v vs %v: plaintext order %d, term order %d", values[i], values[j], want, got)
			}
		}
	}
}

func TestLiveTermOrderIsPlaintextOrder(t *testing.T) {
	c := liveClient(t)
	cipher := c.DefaultKeyset()
	for _, kind := range []TermKind{Ore, Ope} {
		t.Run(kind.String(), func(t *testing.T) {
			t.Run("uint32", func(t *testing.T) {
				orderProperty(t, cipher, kind, cmp.Compare[uint32])
				adjacentProperty(t, cipher, kind, []uint32{0, 1, 2, 255, 256, 257, 65535, 65536, 1<<31 - 1, 1 << 31, 1<<32 - 2, 1<<32 - 1}, cmp.Compare[uint32])
			})
			t.Run("uint64", func(t *testing.T) {
				orderProperty(t, cipher, kind, cmp.Compare[uint64])
				adjacentProperty(t, cipher, kind, []uint64{0, 1, 1<<32 - 1, 1 << 32, 1<<63 - 1, 1 << 63, 1<<64 - 1}, cmp.Compare[uint64])
			})
			t.Run("int64", func(t *testing.T) {
				orderProperty(t, cipher, kind, cmp.Compare[int64])
				adjacentProperty(t, cipher, kind, []int64{-1 << 63, -1<<63 + 1, -2, -1, 0, 1, 2, 1<<63 - 1}, cmp.Compare[int64])
			})
			t.Run("string", func(t *testing.T) {
				// Strings order by their UTF-8 bytes; a prefix orders before
				// its extensions.
				orderProperty(t, cipher, kind, func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
				adjacentProperty(t, cipher, kind, []string{"", "a", "aa", "ab", "b", "ba", "\x7f", "é", "éa"}, func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
			})
			t.Run("bytes", func(t *testing.T) {
				orderProperty(t, cipher, kind, bytes.Compare)
				adjacentProperty(t, cipher, kind, [][]byte{{}, {0}, {0, 0}, {0, 1}, {1}, {255}, {255, 0}}, bytes.Compare)
			})
		})
	}
}
