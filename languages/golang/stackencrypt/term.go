package stackencrypt

import (
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

// OreTerm is an order-revealing term (CLLW ORE): the raw term bytes. The
// comparison is the database's (EQL's ORE operators); this binding does not
// compare terms in Go.
type OreTerm []byte

// OpeTerm is an order-preserving term (CLLW OPE): the raw term bytes,
// ordered as the values they encode.
type OpeTerm []byte

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
