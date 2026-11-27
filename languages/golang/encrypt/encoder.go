package encrypt

import (
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/frame"
)

// Encryptable is a type that writes its own value. A field of such a type is
// sealed as the one value its EncryptValue writes, where the SDK would
// otherwise write the field by its Go type: a money type that writes its
// cents with Int64, say. The value must be of the field's declared kind; the
// engine refuses any other.
//
// A nil pointer to an Encryptable is written as a null, and EncryptValue is
// not called.
type Encryptable interface {
	// EncryptValue writes exactly one value to enc, through one of its
	// methods. A second value, or none, fails the encode, as does a
	// returned error.
	EncryptValue(enc Encoder) error
}

// Encoder takes the one value an Encryptable writes. Only the Encoder handed
// to EncryptValue can be written to; the zero Encoder panics.
//
// An error, such as a string that is not UTF-8 or a date that does not
// exist, fails the whole encode with ErrEncoding. Methods called after an
// error do nothing.
type Encoder struct {
	enc frame.Encoder
}

// Null writes a null.
func (e Encoder) Null() { e.enc.Null() }

// Bool writes a bool.
func (e Encoder) Bool(v bool) { e.enc.Bool(v) }

// Int8 writes an int8.
func (e Encoder) Int8(v int8) { e.enc.Int8(v) }

// Int16 writes an int16.
func (e Encoder) Int16(v int16) { e.enc.Int16(v) }

// Int32 writes an int32.
func (e Encoder) Int32(v int32) { e.enc.Int32(v) }

// Int64 writes an int64.
func (e Encoder) Int64(v int64) { e.enc.Int64(v) }

// Int128 writes an Int128.
func (e Encoder) Int128(v Int128) { e.enc.Int128(frame.Int128(v)) }

// Uint8 writes a uint8.
func (e Encoder) Uint8(v uint8) { e.enc.UInt8(v) }

// Uint16 writes a uint16.
func (e Encoder) Uint16(v uint16) { e.enc.UInt16(v) }

// Uint32 writes a uint32.
func (e Encoder) Uint32(v uint32) { e.enc.UInt32(v) }

// Uint64 writes a uint64.
func (e Encoder) Uint64(v uint64) { e.enc.UInt64(v) }

// Uint128 writes a Uint128.
func (e Encoder) Uint128(v Uint128) { e.enc.UInt128(frame.Uint128(v)) }

// Float32 writes a float32, bit for bit.
func (e Encoder) Float32(v float32) { e.enc.Float32(v) }

// Float64 writes a float64, bit for bit.
func (e Encoder) Float64(v float64) { e.enc.Float64(v) }

// String writes a string, which must be valid UTF-8.
func (e Encoder) String(v string) { e.enc.String(v) }

// Bytes writes bytes.
func (e Encoder) Bytes(v []byte) { e.enc.Bytes(v) }

// Date writes a date, which must exist.
func (e Encoder) Date(v Date) { e.enc.Date(frame.Date(v)) }

// Timestamp writes an instant, to the nanosecond. Its location and monotonic
// reading are not written.
func (e Encoder) Timestamp(v time.Time) { e.enc.Timestamp(v) }

// Decimal writes a decimal. A zero is written without a sign.
func (e Encoder) Decimal(v Decimal) { e.enc.Decimal(frame.Decimal(v)) }

// UUID writes a UUID.
func (e Encoder) UUID(v UUID) { e.enc.UUID(frame.UUID(v)) }
