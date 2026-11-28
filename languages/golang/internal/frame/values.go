package frame

import (
	"errors"
	"math/big"
	"strings"
	"time"
)

var (
	ErrIntegerRange     = errors.New("frame: integer is outside its 128-bit range")
	ErrInvalidDate      = errors.New("frame: invalid date")
	ErrInvalidTimestamp = errors.New("frame: invalid timestamp")
	ErrInvalidDecimal   = errors.New("frame: invalid or out-of-range decimal")
	ErrNonFiniteDecimal = errors.New("frame: decimal must be finite")
	ErrInvalidUUID      = errors.New("frame: invalid UUID")
	ErrInvalidTagged    = errors.New("frame: a tagged value must be a physical scalar with a logical id that this version does not know")
)

// Int128 is a signed 128-bit integer in two's complement, in little-endian
// byte order.
type Int128 [16]byte

// Uint128 is an unsigned 128-bit integer in little-endian byte order.
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

// These constants are the range of dates and instants that the encoding
// accepts:
//
//   - A date has a year from -9999 through 9999.
//   - An instant is from -009999-01-02T01:59:59Z through
//     9999-12-30T22:00:00.999999999Z.
//
// The range is the one that jiff accepts. jiff is the date and time library
// that the Rust code uses. Every language uses the same range. A value that
// one language seals can therefore be opened in every other language.
const (
	minDateYear         = -9999
	maxDateYear         = 9999
	minTimestampSeconds = -377705023201 // -009999-01-02T01:59:59Z
	maxTimestampSeconds = 253402207200  // 9999-12-30T22:00:00Z
)

// Date is a date in the proleptic Gregorian calendar, with no time and no
// time zone. The year is from -9999 through 9999. Year zero and the years
// before it are valid.
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

// DaysFromCE returns the day number that the encoding stores for d. Day 1 is
// 1 January of year 1. The numbering never changes.
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

// Timestamp is an instant, as seconds and nanoseconds since the Unix epoch.
// Use it when the caller has those two numbers and no time.Time. The codec
// only encodes a Timestamp. A timestamp decodes as a time.Time.
//
// Validate refuses two kinds of Timestamp:
//
//   - One whose Nanoseconds is one billion or more. Such a value is a leap
//     second. A leap second has no count since the epoch. The rest of the
//     codec refuses a leap second too.
//   - An instant outside the range that the encoding accepts.
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

// UUID is the sixteen bytes of a UUID. [ParseUUID] reads the hyphenated
// hexadecimal form. [UUID.String] writes that form in lower case.
//
// The codec writes a UUID as bytes with the logical type Uuid. A logical
// type is a meaning that the encoding records for a scalar. Uuid has no tag
// byte of its own. The codec therefore writes a UUID in the envelope. The
// envelope starts with the tag byte 0xF3.
//
// To the codec, any other UUID type is a [16]byte, so the codec writes it as
// bytes. One such type is github.com/google/uuid.UUID. Convert a value of
// that type first, with UUID(id). Rust and Node then read it as a UUID.
type UUID [16]byte

// ParseUUID reads a UUID in its hyphenated form: groups of 8, 4, 4, 4, and
// 12 hexadecimal digits. The digits can be in upper or lower case. ParseUUID
// returns [ErrInvalidUUID] for any other text.
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

// String returns u in its hyphenated form, in lower case.
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

// Tagged is a scalar with a logical type that this version of the codec does
// not know. A newer client can write such a value. The codec decodes it as a
// Tagged, and encodes a Tagged as the same bytes. So the codec neither loses
// the value nor treats it as a plain scalar.
//
// ID and Param are the id and the parameter of the logical type, as the
// envelope records them. ID must be greater than every id this version
// knows. V is the scalar, as the Go type that the codec decodes it as. V
// must be one of these:
//
//   - nil
//   - a bool
//   - an integer or a float of any width
//   - an Int128 or a Uint128
//   - a string
//   - a []byte
//
// The codec writes an int as an Int64 and a uint as a Uint64, as it does for
// every value. A V of type int therefore decodes as an int64, and a V of
// type uint decodes as a uint64.
type Tagged struct {
	ID    uint8
	Param uint8
	V     any
}

// Decimal is a finite base-10 number. The value is Coefficient times 10 to
// the power of -Scale. The value is negative when Negative is set.
//
// Coefficient is an unsigned 96-bit integer in little-endian byte order.
// Scale is at most 28. That is the limit of the Rust crate rust_decimal. The
// codec keeps Scale as given, so it keeps trailing zeroes.
//
// A zero has no sign. The text "-0.00" parses as 0.00, and a negative zero
// encodes and decodes as zero. Each of these keeps the scale.
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

// ParseDecimal reads a number written in fixed-point decimal form, and never
// rounds. ParseDecimal returns [ErrInvalidDecimal] for text that is not such
// a number. ParseDecimal returns the same error for a number that a Decimal
// cannot represent exactly. ParseDecimal returns [ErrNonFiniteDecimal] for
// NaN and for an infinity. A caller can therefore tell those two cases apart
// from other bad text.
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

// Normalized returns d, with Negative cleared when d is zero.
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
