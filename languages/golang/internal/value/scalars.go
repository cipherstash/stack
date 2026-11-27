package vcvalue

import (
	"errors"
	"math/big"
	"strings"
	"time"
)

var (
	ErrIntegerRange     = errors.New("vcvalue: integer is outside its 128-bit range")
	ErrInvalidDate      = errors.New("vcvalue: invalid date")
	ErrInvalidTimestamp = errors.New("vcvalue: invalid timestamp")
	ErrInvalidDecimal   = errors.New("vcvalue: invalid or out-of-range decimal")
	ErrNonFiniteDecimal = errors.New("vcvalue: decimal must be finite")
	ErrInvalidUUID      = errors.New("vcvalue: invalid UUID")
	ErrInvalidTagged    = errors.New("vcvalue: a tagged value must hold a physical scalar under an unknown logical id")
	ErrInvalidFixedType = errors.New("vcvalue: not a fixed-width type")
)

// Int128 is a signed two's-complement integer in little-endian byte order.
type Int128 [16]byte

// Uint128 is an unsigned integer in little-endian byte order.
type Uint128 [16]byte

func littleInteger(value *big.Int) [16]byte {
	var out [16]byte
	bytes := value.Bytes()
	for i, b := range bytes {
		out[len(bytes)-1-i] = b
	}
	return out
}

func ParseInt128(s string) (Int128, error) {
	value, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return Int128{}, ErrIntegerRange
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	if value.Cmp(new(big.Int).Neg(new(big.Int).Set(limit))) < 0 || value.Cmp(limit) >= 0 {
		return Int128{}, ErrIntegerRange
	}
	if value.Sign() < 0 {
		value.Add(value, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return Int128(littleInteger(value)), nil
}

func ParseUint128(s string) (Uint128, error) {
	value, ok := new(big.Int).SetString(s, 10)
	if !ok || value.Sign() < 0 || value.BitLen() > 128 {
		return Uint128{}, ErrIntegerRange
	}
	return Uint128(littleInteger(value)), nil
}

func bigInteger(value [16]byte) *big.Int {
	var be [16]byte
	for i, b := range value {
		be[15-i] = b
	}
	return new(big.Int).SetBytes(be[:])
}
func (v Uint128) String() string { return bigInteger([16]byte(v)).String() }
func (v Int128) String() string {
	value := bigInteger([16]byte(v))
	if v[15]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return value.String()
}

// The wire's range is jiff's in every binding (vitaminc#626), so a value
// one binding seals, every binding opens: dates in years -9999 through
// 9999, and instants from -009999-01-02T01:59:59Z through
// 9999-12-30T22:00:00.999999999Z.
const (
	minDateYear         = -9999
	maxDateYear         = 9999
	minTimestampSeconds = -377705023201 // -009999-01-02T01:59:59Z
	maxTimestampSeconds = 253402207200  // 9999-12-30T22:00:00Z
)

// Date is a proleptic Gregorian calendar date, without time or timezone.
// Its range is the wire's, years -9999 through 9999, including year zero
// and BCE dates.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

func (d Date) Validate() error {
	if d.Year < minDateYear || d.Year > maxDateYear || d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 {
		return ErrInvalidDate
	}
	t := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
	if t.Year() != d.Year || t.Month() != d.Month || t.Day() != d.Day {
		return ErrInvalidDate
	}
	return nil
}

// DaysFromCE returns the frozen wire day count (0001-01-01 is day 1).
func (d Date) DaysFromCE() (int32, error) {
	if err := d.Validate(); err != nil {
		return 0, err
	}
	return int32(time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC).Unix()/86400 + 719163), nil
}

func DateFromDaysCE(days int32) (Date, error) {
	t := time.Unix((int64(days)-719163)*86400, 0).UTC()
	d := Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}
	return d, d.Validate()
}

// Timestamp is an instant as Unix seconds and nanoseconds, for a caller
// that holds the parts rather than a time.Time. Timestamps decode to
// time.Time; this type only encodes. A leap second (nanoseconds of one
// billion or more) has no count since the epoch and is refused, as it is
// everywhere in the model (ADR 0001), and so is an instant outside the
// wire's range.
type Timestamp struct {
	Seconds     int64
	Nanoseconds uint32
}

func (t Timestamp) Validate() error {
	if t.Seconds < minTimestampSeconds || t.Seconds > maxTimestampSeconds || t.Nanoseconds >= 1000000000 {
		return ErrInvalidTimestamp
	}
	return nil
}

// UUID is sixteen bytes under the Uuid logical type: it travels in the
// 0xF3 envelope, since the type has no shorthand tag. ParseUUID reads the
// hyphenated hexadecimal spelling and String writes it in lower case.
//
// Another UUID type, such as github.com/google/uuid.UUID, is a plain
// [16]byte to the codec and is written as bytes. Convert it first, with
// vcvalue.UUID(id), so that Rust and Node read it as a UUID.
type UUID [16]byte

// ParseUUID reads the hyphenated spelling, 8-4-4-4-12 hexadecimal digits in
// either case, and returns ErrInvalidUUID for anything else.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return UUID{}, ErrInvalidUUID
	}
	hexDigits := strings.ReplaceAll(s, "-", "")
	if len(hexDigits) != 32 {
		return UUID{}, ErrInvalidUUID
	}
	for i := range u {
		hi, ok1 := hexDigit(hexDigits[2*i])
		lo, ok2 := hexDigit(hexDigits[2*i+1])
		if !ok1 || !ok2 {
			return UUID{}, ErrInvalidUUID
		}
		u[i] = hi<<4 | lo
	}
	return u, nil
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// String is the hyphenated spelling in lower case.
func (u UUID) String() string {
	const digits = "0123456789abcdef"
	var out [36]byte
	j := 0
	for i, b := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j++
		}
		out[j] = digits[b>>4]
		out[j+1] = digits[b&0x0f]
		j += 2
	}
	return string(out[:])
}

// Tagged carries a scalar under a logical type this build does not know:
// the envelope's id and parameter, and the physical value as the Go native
// of its kind. A value from a newer client is read and re-encoded unchanged
// rather than dropped or mistaken for its bare physical value. V must be a
// physical scalar (nil, bool, an integer or float width, Int128, Uint128,
// string or []byte); ID must be above the ids this build knows. An int or
// uint is written as Int64 or UInt64, as everywhere else in the codec, so
// it reads back as int64 or uint64.
type Tagged struct {
	ID    uint8
	Param uint8
	V     any
}

// Decimal is a finite base-10 value: sign * Coefficient * 10^-Scale.
// Coefficient is an unsigned 96-bit little-endian integer. Scale is retained,
// including trailing zeroes, and must be at most 28 (rust_decimal's range).
// A zero has no sign: "-0.00" parses, decodes and encodes as 0.00 with its
// scale kept (ADR 0001).
type Decimal struct {
	Coefficient [12]byte
	Scale       uint8
	Negative    bool
}

func (d Decimal) Validate() error {
	if d.Scale > 28 {
		return ErrInvalidDecimal
	}
	return nil
}

// ParseDecimal accepts exact fixed-point decimal text without rounding.
// NaN and infinities have their own error so callers can reject them by type.
func ParseDecimal(s string) (Decimal, error) {
	switch strings.ToLower(s) {
	case "nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity":
		return Decimal{}, ErrNonFiniteDecimal
	}
	var d Decimal
	if strings.HasPrefix(s, "-") {
		d.Negative = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 || len(parts[0]) == 0 {
		return Decimal{}, ErrInvalidDecimal
	}
	if len(parts) == 2 {
		if len(parts[1]) == 0 || len(parts[1]) > 28 {
			return Decimal{}, ErrInvalidDecimal
		}
		d.Scale = uint8(len(parts[1]))
	}
	digits := strings.Join(parts, "")
	for _, c := range digits {
		if c < '0' || c > '9' {
			return Decimal{}, ErrInvalidDecimal
		}
	}
	if len(strings.TrimLeft(digits, "0")) > 29 {
		return Decimal{}, ErrInvalidDecimal
	}
	coefficient, ok := new(big.Int).SetString(digits, 10)
	if !ok || coefficient.BitLen() > 96 {
		return Decimal{}, ErrInvalidDecimal
	}
	raw := littleInteger(coefficient)
	copy(d.Coefficient[:], raw[:12])
	if coefficient.Sign() == 0 {
		d.Negative = false
	}
	return d, nil
}

// IsZero reports whether the coefficient is zero, whatever the scale.
func (d Decimal) IsZero() bool {
	return d.Coefficient == [12]byte{}
}

// Normalized is the decimal with the sign dropped from a zero.
func (d Decimal) Normalized() Decimal {
	if d.IsZero() {
		d.Negative = false
	}
	return d
}

func (d Decimal) String() string {
	var raw [16]byte
	copy(raw[:12], d.Coefficient[:])
	digits := bigInteger(raw).String()
	scale := int(d.Scale)
	if scale > 0 {
		if len(digits) <= scale {
			digits = strings.Repeat("0", scale+1-len(digits)) + digits
		}
		digits = digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
	}
	if d.Negative {
		digits = "-" + digits
	}
	return digits
}
