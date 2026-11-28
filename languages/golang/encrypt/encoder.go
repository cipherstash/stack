package encrypt

import (
	"fmt"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/frame"
)

// Encryptable is the interface of a type that writes its own value. Without
// it, the SDK writes a field by its Go type. With it, the field is sealed as
// the one value that EncryptValue writes. An example is a money type that
// writes its cents with Int64.
//
// The value must be of the kind that the field declares. The engine refuses
// a value of any other kind.
//
// The SDK writes a nil pointer to an Encryptable as a null. EncryptValue is
// not called for a nil pointer.
type Encryptable interface {
	// EncryptValue writes exactly one value to enc, with one of the methods
	// of enc. The encode fails if EncryptValue writes no value, writes a
	// second value, or returns an error.
	EncryptValue(enc Encoder) error
}

// Encoder receives the one value that an Encryptable writes. Use only the
// Encoder that EncryptValue is given. The zero Encoder records nothing, and
// its Err method returns an error that says so.
//
// An error fails the whole encode with ErrEncoding. One example is a string
// that is not valid UTF-8. Another is a date that does not exist. A method
// called after an error does nothing.
type Encoder struct {
	enc frame.Encoder
}

// Err returns the first error of the encode so far, wrapped in ErrEncoding,
// or nil. On the zero Encoder, Err always returns an error, because the zero
// Encoder keeps nothing that is written to it.
func (e Encoder) Err() error {
	if !e.enc.Usable() {
		return fmt.Errorf("%w: the zero Encoder records nothing; use the Encoder that EncryptValue is given", ErrEncoding)
	}
	if err := e.enc.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrEncoding, err)
	}
	return nil
}

// Null writes a null.
func (e Encoder) Null() {
	if e.enc.Usable() {
		e.enc.Null()
	}
}

// Bool writes a bool.
func (e Encoder) Bool(v bool) {
	if e.enc.Usable() {
		e.enc.Bool(v)
	}
}

// Int8 writes an int8.
func (e Encoder) Int8(v int8) {
	if e.enc.Usable() {
		e.enc.Int8(v)
	}
}

// Int16 writes an int16.
func (e Encoder) Int16(v int16) {
	if e.enc.Usable() {
		e.enc.Int16(v)
	}
}

// Int32 writes an int32.
func (e Encoder) Int32(v int32) {
	if e.enc.Usable() {
		e.enc.Int32(v)
	}
}

// Int64 writes an int64.
func (e Encoder) Int64(v int64) {
	if e.enc.Usable() {
		e.enc.Int64(v)
	}
}

// Int128 writes an Int128.
func (e Encoder) Int128(v Int128) {
	if e.enc.Usable() {
		e.enc.Int128(frame.Int128(v))
	}
}

// Uint8 writes a uint8.
func (e Encoder) Uint8(v uint8) {
	if e.enc.Usable() {
		e.enc.Uint8(v)
	}
}

// Uint16 writes a uint16.
func (e Encoder) Uint16(v uint16) {
	if e.enc.Usable() {
		e.enc.Uint16(v)
	}
}

// Uint32 writes a uint32.
func (e Encoder) Uint32(v uint32) {
	if e.enc.Usable() {
		e.enc.Uint32(v)
	}
}

// Uint64 writes a uint64.
func (e Encoder) Uint64(v uint64) {
	if e.enc.Usable() {
		e.enc.Uint64(v)
	}
}

// Uint128 writes a Uint128.
func (e Encoder) Uint128(v Uint128) {
	if e.enc.Usable() {
		e.enc.Uint128(frame.Uint128(v))
	}
}

// Float32 writes a float32, with its bits unchanged.
func (e Encoder) Float32(v float32) {
	if e.enc.Usable() {
		e.enc.Float32(v)
	}
}

// Float64 writes a float64, with its bits unchanged.
func (e Encoder) Float64(v float64) {
	if e.enc.Usable() {
		e.enc.Float64(v)
	}
}

// String writes a string. The string must be valid UTF-8.
func (e Encoder) String(v string) {
	if e.enc.Usable() {
		e.enc.String(v)
	}
}

// Bytes writes bytes.
func (e Encoder) Bytes(v []byte) {
	if e.enc.Usable() {
		e.enc.Bytes(v)
	}
}

// Date writes a date. The date must exist.
func (e Encoder) Date(v Date) {
	if e.enc.Usable() {
		e.enc.Date(frame.Date(v))
	}
}

// Timestamp writes an instant, to the nanosecond. The location of v and its
// monotonic clock reading are not written.
func (e Encoder) Timestamp(v time.Time) {
	if e.enc.Usable() {
		e.enc.Timestamp(v)
	}
}

// Decimal writes a decimal. A zero is written without a sign.
func (e Encoder) Decimal(v Decimal) {
	if e.enc.Usable() {
		e.enc.Decimal(frame.Decimal(v))
	}
}

// UUID writes a UUID.
func (e Encoder) UUID(v UUID) {
	if e.enc.Usable() {
		e.enc.UUID(frame.UUID(v))
	}
}
