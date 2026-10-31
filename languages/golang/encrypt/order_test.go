package encrypt_test

import (
	"bytes"
	"cmp"
	"context"
	"math"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"testing/quick"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Property tests of term ordering: random plaintexts, the terms the guest
// stores for them through the generated Probe fields' Encrypt, comparison
// in Go. A query method derives the same bytes, but only for the index
// that answers its operator (ORE, where a field declares both), and only
// over integers, floats and text, so the stored terms reach every index and kind. ORE is
// probabilistic — a wrong comparator or a wrong derivation still agrees
// with plaintext order on many pairs — so a fixed vector set says little;
// hundreds of random pairs per type say more. The index key is the
// deterministic build's, so these run hermetically.

// termOf derives one ORE or OPE term for v.
type termOf[T any] func(ctx context.Context, c *encrypt.Cipher, v T) ([]byte, error)

// storedTerm is the ORE or OPE term a field's Encrypt stores for v, read
// from its output E.
func storedTerm[T, E any](seal func(context.Context, *encrypt.Cipher, T) (E, error), ope bool, ore, opeTerm func(E) []byte) termOf[T] {
	return func(ctx context.Context, c *encrypt.Cipher, v T) ([]byte, error) {
		out, err := seal(ctx, c, v)
		if err != nil {
			return nil, err
		}
		if ope {
			return opeTerm(out), nil
		}
		return ore(out), nil
	}
}

func compareTerms(ope bool, a, b []byte) int {
	if ope {
		return encrypt.OpeTerm(a).Compare(encrypt.OpeTerm(b))
	}
	return encrypt.OreTerm(a).Compare(encrypt.OreTerm(b))
}

// orderProperty checks, for random pairs of T, that the Go comparison of
// their terms agrees with the plaintext order and that a term compares
// equal to itself (derivation is deterministic). gen, when given, replaces
// quick's generator for T.
func orderProperty[T any](t *testing.T, cipher *encrypt.Cipher, ope bool, derive termOf[T], less func(a, b T) int, gen ...func(*rand.Rand) T) {
	t.Helper()
	ctx := context.Background()
	term := func(v T) []byte {
		t.Helper()
		out, err := derive(ctx, cipher, v)
		if err != nil {
			t.Fatalf("term(%v): %v", v, err)
		}
		return out
	}
	sign := func(n int) int { return cmp.Compare(n, 0) }
	holds := func(a, b T) bool {
		ta, tb := term(a), term(b)
		if compareTerms(ope, ta, ta) != 0 || compareTerms(ope, tb, tb) != 0 {
			t.Logf("a term does not compare equal to itself: %v", a)
			return false
		}
		if !bytes.Equal(ta, term(a)) {
			t.Logf("derivation is not deterministic for %v", a)
			return false
		}
		want, got := sign(less(a, b)), sign(compareTerms(ope, ta, tb))
		if got != want {
			t.Logf("%v vs %v: plaintext order %d, term order %d", a, b, want, got)
			return false
		}
		return sign(compareTerms(ope, tb, ta)) == -want
	}
	seed := int64(3)
	if ope {
		seed = 4
	}
	cfg := &quick.Config{MaxCount: 300, Rand: rand.New(rand.NewSource(seed))}
	if len(gen) > 0 {
		cfg.Values = func(args []reflect.Value, r *rand.Rand) {
			for i := range args {
				args[i] = reflect.ValueOf(gen[0](r))
			}
		}
	}
	if err := quick.Check(holds, cfg); err != nil {
		t.Fatal(err)
	}
}

// Neighbouring values are where a comparator that mishandles the last
// differing bit shows; quick's uniform generator almost never produces
// them, so they are checked explicitly alongside.
func adjacentProperty[T any](t *testing.T, cipher *encrypt.Cipher, ope bool, derive termOf[T], values []T, less func(a, b T) int) {
	t.Helper()
	ctx := context.Background()
	terms := make([][]byte, len(values))
	for i, v := range values {
		out, err := derive(ctx, cipher, v)
		if err != nil {
			t.Fatalf("term(%v): %v", v, err)
		}
		terms[i] = out
	}
	for i := range values {
		for j := range values {
			if got, want := compareTerms(ope, terms[i], terms[j]), cmp.Compare(less(values[i], values[j]), 0); got != want {
				t.Errorf("%v vs %v: plaintext order %d, term order %d", values[i], values[j], want, got)
			}
		}
	}
}

// foldedAlphabet holds characters that text's order key keeps as they are.
// Text orders by its fold (ADR-0002): NFD, full case folding, NFD again,
// accents dropped, NFC. So two strings order by their UTF-8 bytes when the
// fold leaves both unchanged: lower-case letters with no accent, digits,
// space and ASCII punctuation. The non-ASCII letters here are already
// folded and have no decomposition, so multi-byte UTF-8 ordering is still
// covered. Upper case, accents and the sharp s are checked as ties below.
var foldedAlphabet = []rune("abcdefghijklmnopqrstuvwxyz0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\u0436\u03c9\u4e2d")

func foldedString(r *rand.Rand) string {
	out := make([]rune, r.Intn(24))
	for i := range out {
		out[i] = foldedAlphabet[r.Intn(len(foldedAlphabet))]
	}
	return string(out)
}

// floatOrder is ADR-0002's order of floats, which is Postgres's float8
// order: -0.0 is 0.0, and every NaN is one value, above +Inf.
func floatOrder[F float32 | float64](a, b F) int {
	an, bn := a != a, b != b
	switch {
	case an && bn:
		return 0
	case an:
		return 1
	case bn:
		return -1
	}
	return cmp.Compare(a, b)
}

// floatValues are the edges of a float's order: both infinities, the
// largest and smallest magnitudes, both zeros, and NaNs of several signs
// and payloads, which are one value.
func floatValues() []float64 {
	return []float64{
		math.Inf(-1), -math.MaxFloat64, -1.5, -math.SmallestNonzeroFloat64,
		math.Copysign(0, -1), 0, math.SmallestNonzeroFloat64, 1.5, math.MaxFloat64, math.Inf(1),
		math.NaN(), math.Float64frombits(0xfff8_0000_0000_0000), math.Float64frombits(0x7ff8_0000_0000_beef),
	}
}

// inOrder orders strings by their place in values, for a list written in
// the order the fold gives it.
func inOrder(values []string) func(a, b string) int {
	return func(a, b string) int {
		return cmp.Compare(slices.Index(values, a), slices.Index(values, b))
	}
}

func TestTermOrderIsPlaintextOrder(t *testing.T) {
	c := deterministicClient(t)
	cipher := c.DefaultKeyset()
	f := testusers.ProbeFields
	byteOrder := func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) }
	same := func(a, b string) int { return 0 }
	for _, ope := range []bool{false, true} {
		name := "ore"
		if ope {
			name = "ope"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("uint32", func(t *testing.T) {
				d := storedTerm(f.U32.Encrypt, ope,
					func(e testusers.EncryptedProbeU32) []byte { return e.Ore },
					func(e testusers.EncryptedProbeU32) []byte { return e.Ope })
				orderProperty(t, cipher, ope, d, cmp.Compare[uint32])
				adjacentProperty(t, cipher, ope, d, []uint32{0, 1, 2, 255, 256, 257, 65535, 65536, 1<<31 - 1, 1 << 31, 1<<32 - 2, 1<<32 - 1}, cmp.Compare[uint32])
			})
			t.Run("uint64", func(t *testing.T) {
				d := storedTerm(f.U64.Encrypt, ope,
					func(e testusers.EncryptedProbeU64) []byte { return e.Ore },
					func(e testusers.EncryptedProbeU64) []byte { return e.Ope })
				orderProperty(t, cipher, ope, d, cmp.Compare[uint64])
				adjacentProperty(t, cipher, ope, d, []uint64{0, 1, 1<<32 - 1, 1 << 32, 1<<63 - 1, 1 << 63, 1<<64 - 1}, cmp.Compare[uint64])
			})
			t.Run("int64", func(t *testing.T) {
				d := storedTerm(f.I64.Encrypt, ope,
					func(e testusers.EncryptedProbeI64) []byte { return e.Ore },
					func(e testusers.EncryptedProbeI64) []byte { return e.Ope })
				orderProperty(t, cipher, ope, d, cmp.Compare[int64])
				adjacentProperty(t, cipher, ope, d, []int64{-1 << 63, -1<<63 + 1, -2, -1, 0, 1, 2, 1<<63 - 1}, cmp.Compare[int64])
			})
			t.Run("string", func(t *testing.T) {
				d := storedTerm(f.S.Encrypt, ope,
					func(e testusers.EncryptedProbeS) []byte { return e.Ore },
					func(e testusers.EncryptedProbeS) []byte { return e.Ope })
				// Strings order by the UTF-8 bytes of their folded form; a
				// prefix orders before its extensions. See foldedAlphabet.
				orderProperty(t, cipher, ope, d, byteOrder, foldedString)
				adjacentProperty(t, cipher, ope, d, []string{"", "a", "aa", "ab", "b", "ba", "ж", "ω", "中"}, byteOrder)
				// The fold drops case and accents and expands ß, so the terms
				// cannot tell these apart.
				adjacentProperty(t, cipher, ope, d, []string{"a", "A"}, same)
				adjacentProperty(t, cipher, ope, d, []string{"e", "\u00e9", "\u00c9", "e\u0301"}, same)
				adjacentProperty(t, cipher, ope, d, []string{"ss", "\u00df", "SS"}, same)
				adjacentProperty(t, cipher, ope, d, []string{"caf\u00e9", "CAFE", "Cafe\u0301"}, same)
				// Mixed case and accents order by the fold: Zoe after alice,
				// and an accented letter beside its base letter.
				names := []string{"alice", "Bob", "eclair", "\u00c9lan", "emu", "Zoe"}
				adjacentProperty(t, cipher, ope, d, names, inOrder(names))
			})
			t.Run("float64", func(t *testing.T) {
				d := storedTerm(f.F64.Encrypt, ope,
					func(e testusers.EncryptedProbeF64) []byte { return e.Ore },
					func(e testusers.EncryptedProbeF64) []byte { return e.Ope })
				// Every bit pattern, so every exponent is drawn: testing/quick's
				// default scales by MaxFloat64 and draws only huge values.
				orderProperty(t, cipher, ope, d, floatOrder[float64], func(r *rand.Rand) float64 {
					return math.Float64frombits(r.Uint64())
				})
				adjacentProperty(t, cipher, ope, d, floatValues(), floatOrder[float64])
			})
			t.Run("float32", func(t *testing.T) {
				d := storedTerm(f.F32.Encrypt, ope,
					func(e testusers.EncryptedProbeF32) []byte { return e.Ore },
					func(e testusers.EncryptedProbeF32) []byte { return e.Ope })
				orderProperty(t, cipher, ope, d, floatOrder[float32], func(r *rand.Rand) float32 {
					return math.Float32frombits(r.Uint32())
				})
				var values []float32
				for _, v := range floatValues() {
					values = append(values, float32(v))
				}
				values = append(values, math.SmallestNonzeroFloat32, -math.SmallestNonzeroFloat32, math.MaxFloat32)
				adjacentProperty(t, cipher, ope, d, values, floatOrder[float32])
			})
			t.Run("bytes", func(t *testing.T) {
				d := storedTerm(f.B.Encrypt, ope,
					func(e testusers.EncryptedProbeB) []byte { return e.Ore },
					func(e testusers.EncryptedProbeB) []byte { return e.Ope })
				orderProperty(t, cipher, ope, d, bytes.Compare)
				adjacentProperty(t, cipher, ope, d, [][]byte{{}, {0}, {0, 0}, {0, 1}, {1}, {255}, {255, 0}}, bytes.Compare)
			})
		})
	}
}

// The generated ordering methods on a text field derive the term its
// Encrypt stores for the folded value, and Between orders its bounds by
// their folds.
func TestTextOrderingMethodsFoldTheValue(t *testing.T) {
	c := deterministicClient(t)
	cipher := c.DefaultKeyset()
	ctx := context.Background()
	f := testusers.ProbeFields
	stored, err := f.S.Encrypt(ctx, cipher, "cafe")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"cafe", "Caf\u00e9", "CAFE", "cafe\u0301"} {
		lt, err := f.S.Lt(ctx, cipher, v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(lt, stored.Ore) {
			t.Errorf("Lt(%q) is not the stored term of cafe", v)
		}
	}
	r, err := f.S.Between(ctx, cipher, "a", "Zoe")
	if err != nil {
		t.Fatal(err)
	}
	if r.Low.Compare(r.High) >= 0 {
		t.Errorf("a should order below Zoe")
	}
	// A range inverted once folded is not refused, as SQL's BETWEEN is
	// not: it matches nothing.
	inverted, err := f.S.Between(ctx, cipher, "b", "A")
	if err != nil {
		t.Fatalf("Between(b, A): %v", err)
	}
	if inverted.Low.Compare(inverted.High) <= 0 {
		t.Errorf("Between(b, A): A folds to a, below b")
	}
	tie, err := f.S.Between(ctx, cipher, "A", "a")
	if err != nil {
		t.Fatal(err)
	}
	if tie.Low.Compare(tie.High) != 0 {
		t.Errorf("Between(A, a) is one folded value")
	}
}
