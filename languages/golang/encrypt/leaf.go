package encrypt

import (
	"database/sql/driver"
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// Sealed is one encrypted leaf: the frozen stack-encrypt storage encoding
// (version, keyset id, IV, ZeroKMS tag, ciphertext), exactly what a
// database column holds. It is a distinct type from vcvalue.Sealed on
// purpose: a stack-encrypt leaf is not decryptable by vitaminc-encrypt and
// must never scan or marshal where one belongs.
type Sealed []byte

// SealedNone is the authenticated marker for an absent value (a nil
// pointer, a Null) inside a ciphertext.
type SealedNone []byte

// SealedEmptySeq is the authenticated marker for an empty sequence.
type SealedEmptySeq []byte

// SealedEmptyMap is the authenticated marker for an empty map.
type SealedEmptyMap []byte

// Value implements driver.Valuer, binding the leaf as a byte column.
func (s Sealed) Value() (driver.Value, error) { return []byte(s), nil }

// Value implements driver.Valuer.
func (s SealedNone) Value() (driver.Value, error) { return []byte(s), nil }

// Value implements driver.Valuer.
func (s SealedEmptySeq) Value() (driver.Value, error) { return []byte(s), nil }

// Value implements driver.Valuer.
func (s SealedEmptyMap) Value() (driver.Value, error) { return []byte(s), nil }

// Scan implements sql.Scanner, loading a leaf from a byte column.
func (s *Sealed) Scan(src any) error {
	b, err := scanBytes("Sealed", src)
	*s = b
	return err
}

// Scan implements sql.Scanner.
func (s *SealedNone) Scan(src any) error {
	b, err := scanBytes("SealedNone", src)
	*s = b
	return err
}

// Scan implements sql.Scanner.
func (s *SealedEmptySeq) Scan(src any) error {
	b, err := scanBytes("SealedEmptySeq", src)
	*s = b
	return err
}

// Scan implements sql.Scanner.
func (s *SealedEmptyMap) Scan(src any) error {
	b, err := scanBytes("SealedEmptyMap", src)
	*s = b
	return err
}

// scanBytes copies a driver byte value: drivers may reuse the source slice
// after Scan returns.
func scanBytes(kind string, src any) ([]byte, error) {
	switch v := src.(type) {
	case []byte:
		out := make([]byte, len(v))
		copy(out, v)
		return out, nil
	case string:
		return []byte(v), nil
	case nil:
		return nil, fmt.Errorf("encrypt: cannot scan NULL into %s", kind)
	default:
		return nil, fmt.Errorf("encrypt: cannot scan %T into %s", src, kind)
	}
}

// leaves is the vcffi.LeafSet of this binding's leaf types.
var leaves = vcffi.LeafSet{
	Classify: func(v any) (vcffi.LeafKind, []byte, bool) {
		switch n := v.(type) {
		case Sealed:
			return vcffi.LeafSingle, n, true
		case SealedNone:
			return vcffi.LeafNone, n, true
		case SealedEmptySeq:
			return vcffi.LeafEmptySeq, n, true
		case SealedEmptyMap:
			return vcffi.LeafEmptyMap, n, true
		default:
			return 0, nil, false
		}
	},
	Make: func(kind vcffi.LeafKind, bytes []byte) any {
		switch kind {
		case vcffi.LeafSingle:
			return Sealed(bytes)
		case vcffi.LeafNone:
			return SealedNone(bytes)
		case vcffi.LeafEmptySeq:
			return SealedEmptySeq(bytes)
		case vcffi.LeafEmptyMap:
			return SealedEmptyMap(bytes)
		default:
			return nil
		}
	},
}

func marshalCipherText(v any) ([]byte, error) {
	return vcffi.MarshalCipherText(leaves, v)
}

func unmarshalCipherText(buf []byte) (any, error) {
	return vcffi.UnmarshalCipherText(leaves, buf)
}
