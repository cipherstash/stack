package encrypt

import (
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The value types a struct field can hold beside Go's own, each sealed as
// vitaminc's leaf of that kind (ADR-0002). They are vitaminc's Go value
// types (module vcvalue), not copies: the transport codec writes each one as
// its leaf byte for byte, and an opened value comes back as the same type, so
// a field of one of these types needs no conversion either way.
//
// A time.Time field is a timestamp: it seals the instant to the nanosecond,
// in UTC, and opens as a time.Time in UTC. Its location and monotonic
// reading are not sealed. An equality term is truncated to the microsecond,
// so two instants in the same microsecond match each other.

// Date is a calendar date, with no time of day and no time zone: Year, Month
// and Day, in the proleptic Gregorian calendar, years -262143 to 262142.
// Validate reports a date that does not exist (February 30).
type Date = vcvalue.Date

// DateOf is the calendar day t falls on in its own location: what t.Date()
// returns. A local midnight east of UTC is that day, not the UTC day before
// it.
func DateOf(t time.Time) Date {
	year, month, day := t.Date()
	return Date{Year: year, Month: month, Day: day}
}

// Int128 is a signed 128-bit integer, two's complement, little-endian.
// ParseInt128 reads one from its decimal text, and String writes it.
type Int128 = vcvalue.Int128

// Uint128 is an unsigned 128-bit integer, little-endian. ParseUint128 reads
// one from its decimal text, and String writes it.
type Uint128 = vcvalue.Uint128

// ParseInt128 reads a signed 128-bit integer from decimal text, refusing a
// value outside its range.
func ParseInt128(s string) (Int128, error) { return vcvalue.ParseInt128(s) }

// ParseUint128 reads an unsigned 128-bit integer from decimal text, refusing
// a negative value or one outside its range.
func ParseUint128(s string) (Uint128, error) { return vcvalue.ParseUint128(s) }

// Decimal is a finite decimal number with its scale: "1.50" is not "1.5",
// and opens as it was sealed. Its mantissa fits 96 bits and its scale is at
// most 28, rust_decimal's range. There is no NaN and no infinity: the type
// cannot hold one, and ParseDecimal refuses one. An equality term normalises
// the scale, so 1.5, 1.50 and 1.500 match each other.
type Decimal = vcvalue.Decimal

// ErrNonFiniteDecimal is the error ParseDecimal returns for NaN or an
// infinity.
var ErrNonFiniteDecimal = vcvalue.ErrNonFiniteDecimal

// ParseDecimal reads a decimal from its fixed-point text ("-1234.5600"),
// keeping its scale, without rounding. NaN and the infinities are
// ErrNonFiniteDecimal; a value with more than 28 digits after the point or a
// mantissa past 96 bits is refused too.
func ParseDecimal(s string) (Decimal, error) { return vcvalue.ParseDecimal(s) }
