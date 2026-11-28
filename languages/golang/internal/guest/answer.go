package guest

import (
	"fmt"
	"reflect"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// KindOf returns a phrase that names the kind of a decoded value, such as
// "null", "an object", "a list", "a string", or "a number". The phrase
// never contains the value.
//
// An error uses the phrase to name the kind of value that it got in place
// of the kind that it takes. So a program can log the error without
// leaking the value.
//
// KindOf checks the vcvalue types first, so that it does not report a
// sealed value as bytes. KindOf names any other Go value by its
// reflect.Kind.
func KindOf(v any) string {
	switch v.(type) {
	case nil, vcvalue.TypedNull:
		return "null"
	case vcvalue.Object:
		return "an object"
	case vcvalue.Sealed:
		return "an encrypted value"
	case vcvalue.SealedEmptySeq:
		return "an encrypted empty list"
	case vcvalue.SealedEmptyMap:
		return "an encrypted empty map"
	case vcvalue.Plain:
		return "a passthrough value"
	case vcvalue.Tagged:
		return "a value of a type this build does not define"
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
		return "a value of another kind"
	}
}

// BadAnswer returns the error for an answer that this module cannot read.
// An answer is the value that a guest export returns. The error is
// ErrInternal. The message of the error names the export and the problem.
// The error wraps problem.
//
// The cause is never the caller's input. The guest and this module agree
// on the format of each answer. So an unreadable answer means a bug, or a
// guest that does not match the version of this module. An example is a
// guest built from other source than the module that embeds it.
func BadAnswer(export string, problem error) error {
	return fmt.Errorf("%w: cannot read the guest's answer from %s: %w. The cause is a bug, or a guest that does not match the version of this module", ErrInternal, export, problem)
}

// DecodeAnswer decodes the answer of export from its transport bytes.
//
// When the bytes do not decode, the fault is in the guest, and not in the
// caller's input. DecodeAnswer then returns the ErrInternal error from
// [BadAnswer]. That error names the export and wraps the error from the
// decoder.
func DecodeAnswer(export string, out []byte) (any, error) {
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, BadAnswer(export, err)
	}
	return decoded, nil
}
