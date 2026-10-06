package encrypt

import (
	"bytes"
	"crypto/subtle"
	"database/sql/driver"
	"encoding/binary"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Index is one index on a field, as a generated declaration names it:
// [Equality], [Ore], [Ope], [Match] or [JSON]. The words are the Rust API's
// words for the same behaviour, and a declaration in any language spells
// them the same way.
type Index interface {
	// Output is the index's wire key.
	Output() record.Output
	// String is the index's tag word.
	String() string
}

type index record.Output

func (i index) Output() record.Output { return record.Output(i) }

func (i index) String() string {
	switch record.Output(i) {
	case record.Equality:
		return "equality"
	case record.Match:
		return "match"
	case record.Ore:
		return "ore"
	case record.Ope:
		return "ope"
	}
	return string(i)
}

// The indexes that take no options.
var (
	// Equality is a PRF equality term: 32 bytes, compared with
	// [EqualityTerm.Equal]. Defined for integers, strings and bytes.
	Equality Index = index(record.Equality)
	// Ore is an order-revealing (CLLW ORE) term over any scalar.
	Ore Index = index(record.Ore)
	// Ope is an order-preserving (CLLW OPE) term over any scalar.
	Ope Index = index(record.Ope)
)

// MatchOption is an option of the match index. None is defined yet: the
// engine's data plan carries the match index under its default options, and
// a non-default option has no wire form (stack-encrypt plan builder,
// Additions item 7).
type MatchOption interface {
	matchOption()
}

// Match is a full-text match index: the tokenized positions of a string.
// Strings only.
func Match(options ...MatchOption) Index {
	_ = options // none exist; the type is declared so a declaration reads as the tag does
	return index(record.Match)
}

// JSONOption is an option of the json index.
type JSONOption interface {
	jsonOption()
}

// JSON is the index over a JSON document. The engine does not derive it
// yet: a declaration that names it is refused by stashgen, and at run time
// by the engine.
func JSON(options ...JSONOption) Index {
	_ = options
	return index("json")
}

// termKindCode is the guest's se_term code for an index.
func termKindCode(o record.Output) (uint32, bool) {
	switch o {
	case record.Equality:
		return 1, true
	case record.Match:
		return 2, true
	case record.Ore:
		return 3, true
	case record.Ope:
		return 4, true
	}
	return 0, false
}

// EqualityTerm is a PRF equality term. Two terms derived under the same
// keyset and context from equal values are equal bytes; nothing else about
// the value is revealed.
type EqualityTerm []byte

// Equal compares two equality terms in constant time.
func (t EqualityTerm) Equal(other EqualityTerm) bool {
	return subtle.ConstantTimeCompare(t, other) == 1
}

// MatchTerm is a full-text match term: the positions of the value's tokens
// in the keyset's token space, as little-endian uint16s.
type MatchTerm []byte

// Positions decodes the term into its token positions.
func (t MatchTerm) Positions() ([]uint16, error) {
	if len(t)%2 != 0 {
		return nil, fmt.Errorf("encrypt: match term of %d bytes is not a whole number of positions", len(t))
	}
	out := make([]uint16, len(t)/2)
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(t[2*i:])
	}
	return out, nil
}

// OreTerm is an order-revealing term (CLLW ORE): the raw term bytes. Two
// terms derived under the same keyset and context order as their plaintexts
// through Compare and Less; plain byte order says nothing.
type OreTerm []byte

// Compare orders two ORE terms as their plaintexts: -1, 0 or +1. Ports the
// CLLW comparison of the Rust crate (constant time over the term bytes):
// at the first differing byte the two sides share the PRF block, so they
// differ by exactly the plaintext bit, and the side one greater is the
// greater plaintext. Terms of different lengths (strings, byte slices)
// compare on their common prefix, then the shorter is less.
func (t OreTerm) Compare(other OreTerm) int {
	return compareCLLW(t, other)
}

// Less reports whether t's plaintext orders before other's.
func (t OreTerm) Less(other OreTerm) bool { return t.Compare(other) < 0 }

// OpeTerm is an order-preserving term (CLLW OPE): the raw term bytes,
// ordered as the values they encode under plain byte order, so a database
// compares them with no custom operator.
type OpeTerm []byte

// Compare orders two OPE terms as their plaintexts: bytes.Compare.
func (t OpeTerm) Compare(other OpeTerm) int { return bytes.Compare(t, other) }

// Less reports whether t's plaintext orders before other's.
func (t OpeTerm) Less(other OpeTerm) bool { return t.Compare(other) < 0 }

// JSONTerm is the term of the json index. The engine does not derive it
// yet; the type exists so a generated declaration that names [JSON] has a
// Go type to fail into.
type JSONTerm []byte

// compareCLLW is cllw-ore's compare_lex: compare_slice over the common
// prefix, then by length. For equal-length terms (integers) that is
// compare_slice alone.
func compareCLLW(a, b []byte) int {
	n := min(len(a), len(b))
	if n > 0 {
		if c := compareCLLWSlice(a[:n], b[:n]); c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// compareCLLWSlice is cllw-ore's compare_slice: the first differing byte
// pair is found and judged in constant time; only the final translation
// to an ordering branches, after every secret-dependent step.
func compareCLLWSlice(a, b []byte) int {
	var diffX, diffY, found int
	for i := range a {
		isDiff := 1 - subtle.ConstantTimeByteEq(a[i], b[i])
		record := isDiff & (1 - found)
		diffX = subtle.ConstantTimeSelect(record, int(a[i]), diffX)
		diffY = subtle.ConstantTimeSelect(record, int(b[i]), diffY)
		found = subtle.ConstantTimeSelect(record, isDiff, found)
	}
	// x == y + 1 (mod 256) means a's plaintext bit was the 1 at the first
	// difference.
	greater := subtle.ConstantTimeByteEq(uint8(diffY+1), uint8(diffX))
	switch {
	case found == 0:
		return 0
	case greater == 1:
		return 1
	default:
		return -1
	}
}

// Value implements driver.Valuer.
func (t EqualityTerm) Value() (driver.Value, error) { return []byte(t), nil }

// Value implements driver.Valuer.
func (t MatchTerm) Value() (driver.Value, error) { return []byte(t), nil }

// Value implements driver.Valuer.
func (t OreTerm) Value() (driver.Value, error) { return []byte(t), nil }

// Value implements driver.Valuer.
func (t OpeTerm) Value() (driver.Value, error) { return []byte(t), nil }

// Value implements driver.Valuer.
func (t JSONTerm) Value() (driver.Value, error) { return []byte(t), nil }

// Scan implements sql.Scanner.
func (t *EqualityTerm) Scan(src any) error {
	b, err := scanBytes("EqualityTerm", src)
	*t = b
	return err
}

// Scan implements sql.Scanner.
func (t *MatchTerm) Scan(src any) error {
	b, err := scanBytes("MatchTerm", src)
	*t = b
	return err
}

// Scan implements sql.Scanner.
func (t *OreTerm) Scan(src any) error {
	b, err := scanBytes("OreTerm", src)
	*t = b
	return err
}

// Scan implements sql.Scanner.
func (t *OpeTerm) Scan(src any) error {
	b, err := scanBytes("OpeTerm", src)
	*t = b
	return err
}

// Scan implements sql.Scanner.
func (t *JSONTerm) Scan(src any) error {
	b, err := scanBytes("JSONTerm", src)
	*t = b
	return err
}
