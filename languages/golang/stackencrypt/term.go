package stackencrypt

import (
	"bytes"
	"crypto/subtle"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
)

// TermKind selects which index term a probe or a plan field derives. The
// values are the guest's term-kind codes.
type TermKind uint32

const (
	// Equality is a PRF equality term: 32 bytes, compared with
	// [EqualityTerm.Equal]. Defined for integers, strings and bytes.
	Equality TermKind = 1
	// Match is a full-text match term: the tokenized positions of a string,
	// as little-endian uint16s. Strings only.
	Match TermKind = 2
	// Ore is an order-revealing (CLLW ORE) term over any scalar.
	Ore TermKind = 3
	// Ope is an order-preserving (CLLW OPE) term over any scalar.
	Ope TermKind = 4
)

func (k TermKind) String() string {
	switch k {
	case Equality:
		return "eq"
	case Match:
		return "match"
	case Ore:
		return "ore"
	case Ope:
		return "ope"
	default:
		return fmt.Sprintf("TermKind(%d)", uint32(k))
	}
}

// parseTermKind maps a plan-tag spelling to its kind.
func parseTermKind(s string) (TermKind, bool) {
	switch s {
	case "eq":
		return Equality, true
	case "match":
		return Match, true
	case "ore":
		return Ore, true
	case "ope":
		return Ope, true
	default:
		return 0, false
	}
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
		return nil, fmt.Errorf("stackencrypt: match term of %d bytes is not a whole number of positions", len(t))
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
