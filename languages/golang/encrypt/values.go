package encrypt

import (
	"errors"
	"strings"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/frame"
)

// The value types a struct field can hold beside Go's own. Each is sealed as
// the leaf of its kind, and an opened value comes back as the same
// type, so a field of one of these types needs no conversion either way.
//
// A time.Time field is a timestamp: it seals the instant to the nanosecond,
// in UTC, and opens as a time.Time in UTC. Its location and monotonic
// reading are not sealed. An equality term is truncated to the microsecond,
// so two instants in the same microsecond match each other.

// Date is a calendar date, with no time of day and no time zone: Year, Month
// and Day, in the proleptic Gregorian calendar, years -9999 to 9999.
// Validate reports a date that does not exist (February 30).
//
// The zero Date (year 0, month 0, day 0) is not a date: a Date field must be
// set before it is encrypted or queried, and a zero one is refused with
// ErrEncoding, naming the field. An optional date is a *Date field: nil is
// stored as a sealed null as long as a date, or, with the tag's null=sql, as
// SQL NULL (see stashgen's README, "Optional fields").
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// DateOf is the calendar day t falls on in its own location: what t.Date()
// returns. A local midnight east of UTC is that day, not the UTC day before
// it.
func DateOf(t time.Time) Date {
	year, month, day := t.Date()
	return Date{Year: year, Month: month, Day: day}
}

// Validate reports an error for a date that does not exist, or that is
// outside years -9999 to 9999.
func (d Date) Validate() error { return valueError(frame.Date(d).Validate()) }

// Int128 is a signed 128-bit integer, two's complement, little-endian.
// ParseInt128 reads one from its decimal text, and String writes it.
type Int128 [16]byte

// ParseInt128 reads a signed 128-bit integer from decimal text, refusing a
// value outside its range.
func ParseInt128(s string) (Int128, error) {
	v, err := frame.ParseInt128(s)
	return Int128(v), valueError(err)
}

// String is the integer's decimal text.
func (v Int128) String() string { return frame.Int128(v).String() }

// Uint128 is an unsigned 128-bit integer, little-endian. ParseUint128 reads
// one from its decimal text, and String writes it.
type Uint128 [16]byte

// ParseUint128 reads an unsigned 128-bit integer from decimal text, refusing
// a negative value or one outside its range.
func ParseUint128(s string) (Uint128, error) {
	v, err := frame.ParseUint128(s)
	return Uint128(v), valueError(err)
}

// String is the integer's decimal text.
func (v Uint128) String() string { return frame.Uint128(v).String() }

// Decimal is a finite decimal number with its scale: "1.50" is not "1.5",
// and opens as it was sealed, except that a zero has no sign: -0.00 opens as
// 0.00, at the same scale. Its value is (-1 if Negative) × Coefficient ×
// 10^-Scale, where Coefficient is an unsigned 96-bit little-endian integer
// and Scale is at most 28, rust_decimal's range. There is no NaN and no
// infinity: the type cannot hold one, and ParseDecimal refuses one. An
// equality term normalises the scale, so 1.5, 1.50 and 1.500 match each
// other.
type Decimal struct {
	Coefficient [12]byte
	Scale       uint8
	Negative    bool
}

// ErrNonFiniteDecimal is the error ParseDecimal returns for NaN or an
// infinity.
var ErrNonFiniteDecimal = errors.New("encrypt: decimal must be finite")

// ParseDecimal reads a decimal from its fixed-point text ("-1234.5600"),
// keeping its scale, without rounding. NaN and the infinities are
// ErrNonFiniteDecimal; a value with more than 28 digits after the point or a
// mantissa past 96 bits is refused too.
func ParseDecimal(s string) (Decimal, error) {
	v, err := frame.ParseDecimal(s)
	return Decimal(v), valueError(err)
}

// Validate reports an error for a scale above 28.
func (d Decimal) Validate() error { return valueError(frame.Decimal(d).Validate()) }

// IsZero reports whether the decimal is zero, whatever its scale.
func (d Decimal) IsZero() bool { return frame.Decimal(d).IsZero() }

// String is the decimal's fixed-point text, with its scale: "-1234.5600".
func (d Decimal) String() string { return frame.Decimal(d).String() }

// UUID is a UUID: sixteen bytes, sealed under the UUID logical type, which
// Rust and Node open as a UUID. ParseUUID reads the hyphenated spelling and
// String writes it.
//
// A field of the kind "uuid" (gensupport.UUID) also takes a value of
// another type whose underlying type is [16]byte, such as
// github.com/google/uuid.UUID, and converts it to a UUID. Anywhere else such
// a value is sixteen bytes: convert it with UUID(id) first.
type UUID [16]byte

// ParseUUID reads the hyphenated spelling, 8-4-4-4-12 hexadecimal digits in
// either case.
func ParseUUID(s string) (UUID, error) {
	v, err := frame.ParseUUID(s)
	return UUID(v), valueError(err)
}

// String is the hyphenated spelling in lower case.
func (u UUID) String() string { return frame.UUID(u).String() }

// valueError is the codec's refusal of a value, as this package reports it:
// ErrNonFiniteDecimal for a NaN or an infinity, and otherwise an error whose
// text starts "encrypt: " and that errors.Is still matches to the codec's.
func valueError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, frame.ErrNonFiniteDecimal):
		return ErrNonFiniteDecimal
	}
	return &refusedValue{err: err}
}

type refusedValue struct{ err error }

func (e *refusedValue) Error() string {
	return "encrypt: " + strings.TrimPrefix(e.err.Error(), "frame: ")
}

func (e *refusedValue) Unwrap() error { return e.err }

func init() {
	// The codec writes each of these types as its value type, and decodes
	// that value type as it.
	frame.Publish[Date, frame.Date]()
	frame.Publish[Decimal, frame.Decimal]()
	frame.Publish[Int128, frame.Int128]()
	frame.Publish[Uint128, frame.Uint128]()
	frame.Publish[UUID, frame.UUID]()
	frame.PublishEncryptable(func(v Encryptable, enc frame.Encoder) error {
		return v.EncryptValue(Encoder{enc: enc})
	})
}
