package encrypt

import (
	"errors"
	"strings"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/frame"
)

// The types below are the value types that a struct field can have, in
// addition to Go's own types. Each value is sealed as the leaf of its kind.
// A leaf is one encrypted value. An opened value has the same type, so a
// field of one of these types needs no conversion in either direction.
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

// Validate returns an error for a date that does not exist, and for a date
// outside the years -9999 to 9999.
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

// String returns the integer as decimal text.
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

// String returns the integer as decimal text.
func (v Uint128) String() string { return frame.Uint128(v).String() }

// Decimal is a finite decimal number that keeps its scale. "1.50" is not
// "1.5", and each opens as it was sealed. A zero is the exception, because a
// zero has no sign: -0.00 opens as 0.00, at the same scale.
//
// The value is Coefficient times 10 to the power of -Scale. The value is
// negative when Negative is set. Coefficient is an unsigned 96-bit integer
// in little-endian byte order. Scale is at most 28. That is the limit of the
// Rust crate rust_decimal.
//
// A Decimal cannot be NaN or an infinity, and [ParseDecimal] refuses both.
// An equality term normalises the scale, so 1.5, 1.50, and 1.500 match each
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

// Validate returns an error for a scale above 28.
func (d Decimal) Validate() error { return valueError(frame.Decimal(d).Validate()) }

// IsZero reports whether the decimal is zero, whatever its scale.
func (d Decimal) IsZero() bool { return frame.Decimal(d).IsZero() }

// String returns the decimal as fixed-point text, with its scale, as in
// "-1234.5600".
func (d Decimal) String() string { return frame.Decimal(d).String() }

// UUID is the sixteen bytes of a UUID. A UUID is sealed with the logical
// type UUID, so Rust and Node open it as a UUID. [ParseUUID] reads the
// hyphenated form, and [UUID.String] writes it.
//
// A field of the kind "uuid" (gensupport.UUID) also accepts a value of
// another type whose underlying type is [16]byte. One such type is
// github.com/google/uuid.UUID. The SDK converts that value to a UUID.
// Anywhere else, such a value is sealed as sixteen bytes. Convert it with
// UUID(id) first.
type UUID [16]byte

// ParseUUID reads a UUID in its hyphenated form: groups of 8, 4, 4, 4, and
// 12 hexadecimal digits. The digits can be in upper or lower case.
func ParseUUID(s string) (UUID, error) {
	v, err := frame.ParseUUID(s)
	return UUID(v), valueError(err)
}

// String returns the UUID in its hyphenated form, in lower case.
func (u UUID) String() string { return frame.UUID(u).String() }

// valueError converts an error from the codec into the error that this
// package returns. A NaN or an infinity becomes ErrNonFiniteDecimal. Any
// other error becomes an error whose text starts with "encrypt: ". A call to
// errors.Is still matches that error to the codec's error.
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
	// The codec encodes each of these types as the matching value type of
	// package frame. The codec decodes that value type as the type declared
	// here.
	frame.Publish[Date, frame.Date]()
	frame.Publish[Decimal, frame.Decimal]()
	frame.Publish[Int128, frame.Int128]()
	frame.Publish[Uint128, frame.Uint128]()
	frame.Publish[UUID, frame.UUID]()
	frame.PublishEncryptable(func(v Encryptable, enc frame.Encoder) error {
		return v.EncryptValue(Encoder{enc: enc})
	})
}
