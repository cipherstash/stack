package gensupport

import (
	"fmt"
	"math"
	"reflect"
	"strconv"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
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
// The error names the kind and not the value, which is plaintext.
func asKind(kind Kind, v any) (any, error) {
	if !isInteger(kind) {
		return v, nil
	}
	switch v.(type) {
	case vcvalue.Int128, vcvalue.Uint128:
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

func isInteger(k Kind) bool {
	switch k {
	case Int8, Int16, Int32, Int64, Int128, Uint8, Uint16, Uint32, Uint64, Uint128:
		return true
	}
	return false
}

// integerAs is the integer, given as exactly one of a signed or an unsigned
// value, as the Go type of kind, if it fits.
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
		return int8(i), ok
	case Int16:
		i, ok := inSigned(math.MinInt16, math.MaxInt16)
		return int16(i), ok
	case Int32:
		i, ok := inSigned(math.MinInt32, math.MaxInt32)
		return int32(i), ok
	case Int64:
		i, ok := inSigned(math.MinInt64, math.MaxInt64)
		return i, ok
	case Uint8:
		u, ok := inUnsigned(math.MaxUint8)
		return uint8(u), ok
	case Uint16:
		u, ok := inUnsigned(math.MaxUint16)
		return uint16(u), ok
	case Uint32:
		u, ok := inUnsigned(math.MaxUint32)
		return uint32(u), ok
	case Uint64:
		u, ok := inUnsigned(math.MaxUint64)
		return u, ok
	case Int128, Uint128:
		text := ""
		if signed != nil {
			text = strconv.FormatInt(*signed, 10)
		} else {
			text = strconv.FormatUint(*unsigned, 10)
		}
		if kind == Int128 {
			v, err := vcvalue.ParseInt128(text)
			return v, err == nil
		}
		v, err := vcvalue.ParseUint128(text)
		return v, err == nil
	}
	return nil, false
}
