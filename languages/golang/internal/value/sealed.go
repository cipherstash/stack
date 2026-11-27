package vcvalue

import (
	"database/sql/driver"
	"fmt"
	"math"
)

// Sealed is one encrypted leaf: version(1) || nonce || ciphertext || tag —
// the only frozen byte format in the model. The leading wire-version byte is
// itself authenticated into the leaf's AAD, so a relabeled version fails the
// tag rather than selecting different parsing rules. Sealed is a named type
// so sealed bytes can never be confused with a plaintext []byte value in the
// dynamic ciphertext shape.
//
// Sealed implements driver.Valuer and sql.Scanner, so it stores into and
// loads from a BLOB/BYTEA column with no conversion.
type Sealed []byte

// Value implements driver.Valuer: a Sealed binds as raw bytes.
func (s Sealed) Value() (driver.Value, error) {
	return []byte(s), nil
}

// Scan implements sql.Scanner: a BLOB/BYTEA column loads as a Sealed.
func (s *Sealed) Scan(src any) error {
	b, err := scanLeafBytes(src, "Sealed")
	*s = Sealed(b)
	return err
}

// SealedEmptySeq is the authenticated marker for an empty sequence: with no
// element ciphertexts to bind the AAD, the cipher seals an empty plaintext
// under domain-separated AAD instead. Produced by encrypting an empty array;
// decrypts back to an empty array.
type SealedEmptySeq []byte

// SealedEmptyMap is the authenticated marker for an empty map, the map-shaped
// counterpart of SealedEmptySeq. Produced by encrypting an empty object;
// decrypts back to an empty object.
type SealedEmptyMap []byte

// The marker types implement driver.Valuer and sql.Scanner like Sealed, so a
// column holding one stores and loads without conversion.
//
// ⚠️ The stored bytes do NOT record which leaf kind they are — every leaf is
// the same `version || nonce || ciphertext || tag` shape, and the kind is
// authenticated through domain-separated AAD, not written into the bytes. A
// marker scanned back into the wrong type (e.g. a SealedEmptySeq loaded as
// Sealed) fails decryption with an authentication error and no further hint.
// A column that can hold both real values and empty-composite markers needs
// the schema (or the application) to record which kind it stored; scan into
// the type matching that record.

// Value implements driver.Valuer: the marker binds as raw bytes.
func (s SealedEmptySeq) Value() (driver.Value, error) { return []byte(s), nil }

// Scan implements sql.Scanner — see the leaf-kind caveat above.
func (s *SealedEmptySeq) Scan(src any) error {
	b, err := scanLeafBytes(src, "SealedEmptySeq")
	*s = SealedEmptySeq(b)
	return err
}

// Value implements driver.Valuer: the marker binds as raw bytes.
func (s SealedEmptyMap) Value() (driver.Value, error) { return []byte(s), nil }

// Scan implements sql.Scanner — see the leaf-kind caveat above.
func (s *SealedEmptyMap) Scan(src any) error {
	b, err := scanLeafBytes(src, "SealedEmptyMap")
	*s = SealedEmptyMap(b)
	return err
}

func scanLeafBytes(src any, into string) ([]byte, error) {
	switch b := src.(type) {
	case nil:
		return nil, nil
	case []byte:
		return append([]byte(nil), b...), nil
	default:
		return nil, fmt.Errorf("vcvalue: cannot scan %T into %s", src, into)
	}
}

// Value implements driver.Valuer for passthrough fields, so a map-shaped
// ciphertext binds directly as database named parameters. Only scalar
// natives convert; a container passthrough has no single-column form.
func (p Plain) Value() (driver.Value, error) {
	// Every integer kind the encoder accepts must convert here too: a value
	// that encodes must also bind, or `Plain{V: user.ID}` with `ID int` works
	// until it reaches the database driver.
	switch v := p.V.(type) {
	case nil, bool, int64, float64, string, []byte:
		return v, nil
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case float32:
		return float64(v), nil
	case uint:
		if uint64(v) > math.MaxInt64 {
			return nil, fmt.Errorf("vcvalue: passthrough uint %d overflows the driver's int64", v)
		}
		return int64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return nil, fmt.Errorf("vcvalue: passthrough uint64 %d overflows the driver's int64", v)
		}
		return int64(v), nil
	default:
		return nil, fmt.Errorf("vcvalue: passthrough %T has no single-column driver representation", p.V)
	}
}
