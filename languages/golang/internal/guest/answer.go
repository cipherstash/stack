package guest

import (
	"fmt"
	"reflect"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// KindOf names what a decoded value is, by its kind and never its value:
// "null", "an object", "a list", "a string", "a number", and so on. It is
// what an error says it found where it expected something else, so the
// error can be logged without leaking the value. The vcvalue types are
// named first, so a sealed value is not taken for bytes; any other Go
// value is named by its reflect.Kind.
func KindOf(v any) string {
	switch v.(type) {
	case nil, vcvalue.TypedNull:
		return "null"
	case vcvalue.Object:
		return "an object"
	case vcvalue.Sealed:
		return "a sealed value"
	case vcvalue.SealedEmptySeq:
		return "a sealed empty list"
	case vcvalue.SealedEmptyMap:
		return "a sealed empty map"
	case vcvalue.Plain:
		return "a passthrough value"
	case vcvalue.Tagged:
		return "a value of a type this build does not know"
	case vcvalue.Int128, vcvalue.Uint128:
		return "a number"
	case vcvalue.Date:
		return "a date"
	case vcvalue.Timestamp:
		return "a timestamp"
	case vcvalue.Decimal:
		return "a decimal"
	case vcvalue.UUID:
		return "a UUID"
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Bool:
		return "a boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.String:
		return "a string"
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return "bytes"
		}
		return "a list"
	case reflect.Map:
		return "a map"
	case reflect.Struct:
		return "a struct"
	case reflect.Pointer:
		return "a pointer"
	default:
		return "a single value"
	}
}

// BadAnswer is the error for a guest export's answer this module cannot
// read: ErrInternal, naming the export and what was wrong with the answer,
// which it wraps. The caller's input is not at fault. The answer's shape is
// a contract between the guest and this module, so a bad one is a bug, or a
// guest that does not match this module's version, such as a guest built
// from other source than the module that embeds it.
func BadAnswer(export string, problem error) error {
	return fmt.Errorf("%w: the guest's answer to %s does not read: %w; this is a bug, or a guest that does not match this module's version", ErrInternal, export, problem)
}
