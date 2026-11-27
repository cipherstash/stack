package gensupport

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/frame"
)

// asKind is a sealed field's value as the Go type of its declared kind, the
// width the engine seals it at. A field's kind is its Go type's own unless the
// field is stored as an EQL type of another integer kind (an int16 stored as
// Integer is sealed as an int32, and so is an int64, ADR-0002): then the value
// is converted here, on the host, because nothing below the binding converts.
// Only an integer changes; every other value, and an integer already of its
// kind's width, crosses as it is. A value outside the kind's range is refused
// with encrypt.ErrEncoding: a Go type wider than the kind is accepted by
// stashgen and range checked here, value by value.
//
// A value whose type writes itself (encrypt.Encryptable) crosses as it is too:
// converting it to a built-in integer would drop its EncryptValue, and the
// engine holds what it writes to the field's kind. A write and a query of one
// field both convert here ([Field.Encrypt], [Field.Term]), so they agree.
//
// A UUID field's value crosses as an encrypt.UUID, which the codec writes under
// the uuid logical type. A value of another type whose underlying type is
// [16]byte (github.com/google/uuid.UUID, say) is converted to it here, since
// the codec writes such a value as plain bytes and the engine refuses bytes in a
// UUID field. encrypt.Int128 and Uint128 are integers, not UUIDs, and are not
// converted.
//
// The error names the kind and not the value, which is plaintext.
func asKind(kind Kind, v any) (any, error) {
	if err := checkValue(v); err != nil {
		return nil, err
	}
	if kind == JSON {
		// A document crosses as its JSON text, in a bytes value; the
		// engine parses it. A json.RawMessage is that text; a field of
		// another Go type (a struct, say) is marshalled, explicitly, here.
		return JSONText(v)
	}
	if kind == UUID {
		return asUUID(v), nil
	}
	if !isInteger(kind) {
		return v, nil
	}
	switch v.(type) {
	case encrypt.Int128, encrypt.Uint128, encrypt.Encryptable:
		return v, nil
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return v, nil
	}
	var signed *int64
	var unsigned *uint64
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i := rv.Int()
		signed = &i
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u := rv.Uint()
		unsigned = &u
	default:
		return v, nil
	}
	out, ok := integerAs(kind, signed, unsigned)
	if !ok {
		return nil, fmt.Errorf("%w: a value does not fit the field's kind %s", encrypt.ErrEncoding, kind)
	}
	return out, nil
}

// uuidType is encrypt.UUID's reflect.Type.
var uuidType = reflect.TypeFor[encrypt.UUID]()

// asUUID is v as an encrypt.UUID when its underlying type is [16]byte, and v
// unchanged otherwise: an encrypt.UUID already, a value that writes itself, a
// 128-bit integer, or a value of another shape, which the engine refuses.
func asUUID(v any) any {
	switch v.(type) {
	case encrypt.UUID, encrypt.Int128, encrypt.Uint128, encrypt.Encryptable:
		return v
	}
	rv := reflect.ValueOf(v)
	if rv.IsValid() && rv.Type().ConvertibleTo(uuidType) && rv.Kind() == reflect.Array {
		return rv.Convert(uuidType).Interface()
	}
	return v
}

// errInvalidTimestamp is the refusal of an instant outside years -9999 to
// 9999.
var errInvalidTimestamp = errors.New("encrypt: invalid timestamp: outside years -9999 to 9999")

// checkValue refuses a date, decimal or timestamp the codec cannot write, before
// it reaches the codec, so the caller can name the field: the codec's own
// refusal names neither. A zero encrypt.Date (year 0, month 0, day 0) is not
// a date and is refused here. The error names the type and not the value.
func checkValue(v any) error {
	var err error
	switch v := v.(type) {
	case encrypt.Date:
		err = v.Validate()
	case encrypt.Decimal:
		err = v.Validate()
	case time.Time:
		if (frame.Timestamp{Seconds: v.Unix(), Nanoseconds: uint32(v.Nanosecond())}).Validate() != nil { //nolint:gosec // Nanosecond is in [0, 1e9)
			err = errInvalidTimestamp
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %w", encrypt.ErrEncoding, err)
	}
	return nil
}

func isInteger(k Kind) bool {
	switch k {
	case Int8, Int16, Int32, Int64, Int128, Uint8, Uint16, Uint32, Uint64, Uint128:
		return true
	}
	return false
}

// integerAs is the integer, given as exactly one of a signed or an unsigned
// value, as the Go type of kind, if it fits. A 128-bit kind has no arm: its
// only Go types are encrypt.Int128 and Uint128, which asKind passes through,
// and stashgen refuses a built-in integer field stored as a 128-bit kind, so a
// built-in integer never reaches one here; if one did, it is refused as not
// fitting.
func integerAs(kind Kind, signed *int64, unsigned *uint64) (any, bool) {
	inSigned := func(lo, hi int64) (int64, bool) {
		if signed != nil {
			return *signed, *signed >= lo && *signed <= hi
		}
		return int64(*unsigned), *unsigned <= uint64(hi) //nolint:gosec // range-checked
	}
	inUnsigned := func(hi uint64) (uint64, bool) {
		if unsigned != nil {
			return *unsigned, *unsigned <= hi
		}
		return uint64(*signed), *signed >= 0 && uint64(*signed) <= hi //nolint:gosec // range-checked
	}
	switch kind {
	case Int8:
		i, ok := inSigned(math.MinInt8, math.MaxInt8)
		return int8(i), ok //nolint:gosec // range-checked: ok is false when it does not fit
	case Int16:
		i, ok := inSigned(math.MinInt16, math.MaxInt16)
		return int16(i), ok //nolint:gosec // range-checked: ok is false when it does not fit
	case Int32:
		i, ok := inSigned(math.MinInt32, math.MaxInt32)
		return int32(i), ok //nolint:gosec // range-checked: ok is false when it does not fit
	case Int64:
		i, ok := inSigned(math.MinInt64, math.MaxInt64)
		return i, ok
	case Uint8:
		u, ok := inUnsigned(math.MaxUint8)
		return uint8(u), ok //nolint:gosec // range-checked: ok is false when it does not fit
	case Uint16:
		u, ok := inUnsigned(math.MaxUint16)
		return uint16(u), ok //nolint:gosec // range-checked: ok is false when it does not fit
	case Uint32:
		u, ok := inUnsigned(math.MaxUint32)
		return uint32(u), ok //nolint:gosec // range-checked: ok is false when it does not fit
	case Uint64:
		u, ok := inUnsigned(math.MaxUint64)
		return u, ok
	}
	return nil, false
}
