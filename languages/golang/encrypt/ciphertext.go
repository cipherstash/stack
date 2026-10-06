package encrypt

import (
	"database/sql/driver"
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// Ciphertext is one sealed field as a database column holds it: the frozen
// stack-encrypt leaf encoding (version, keyset id, IV, ZeroKMS tag,
// ciphertext). A generated type holds one for each field sealed in separate
// columns, beside that field's terms. It is a distinct type from vitaminc's
// own leaf on purpose: a stack-encrypt leaf is not decryptable by
// vitaminc-encrypt and must never scan or marshal where one belongs.
//
// A sealed field is one scalar — a string, a number, a bool or a []byte, or
// a type defined over one — and seals as the typed leaf a Rust record
// derives. A struct, slice or map seals only as part of an opaque struct,
// which crosses as one JSON document and is one leaf; stashgen refuses it
// anywhere else, because the engine would seal it as a tree of leaves and a
// column holds one.
type Ciphertext []byte

// Value implements driver.Valuer, binding the leaf as a byte column.
func (c Ciphertext) Value() (driver.Value, error) { return []byte(c), nil }

// Scan implements sql.Scanner, loading a leaf from a byte column.
func (c *Ciphertext) Scan(src any) error {
	b, err := scanBytes("Ciphertext", src)
	*c = b
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

// otherLeaf is a leaf of a kind the SDK does not store: the authenticated
// markers for an absent value, an empty sequence and an empty map, which a
// record field never produces. Decoding one is an error at the use site.
type otherLeaf struct {
	kind  vcffi.LeafKind
	bytes []byte
}

// leaves is the vcffi.LeafSet of this binding's leaf types.
var leaves = vcffi.LeafSet{
	Classify: func(v any) (vcffi.LeafKind, []byte, bool) {
		switch n := v.(type) {
		case Ciphertext:
			return vcffi.LeafSingle, n, true
		case otherLeaf:
			return n.kind, n.bytes, true
		default:
			return 0, nil, false
		}
	},
	Make: func(kind vcffi.LeafKind, bytes []byte) any {
		if kind == vcffi.LeafSingle {
			return Ciphertext(bytes)
		}
		return otherLeaf{kind: kind, bytes: bytes}
	},
}

func marshalCipherText(v any) ([]byte, error) {
	return vcffi.MarshalCipherText(leaves, v)
}

func unmarshalCipherText(buf []byte) (any, error) {
	return vcffi.UnmarshalCipherText(leaves, buf)
}
