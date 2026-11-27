package guest

import (
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// KindOf names what a decoded value is, by its kind and never its value:
// "null", "an object", "a list", "a string", "a number", and so on. It is
// what an error says it found where it expected something else, so the
// error can be logged without leaking the value.
func KindOf(v any) string {
	switch v.(type) {
	case nil, vcvalue.TypedNull:
		return "null"
	case vcvalue.Object:
		return "an object"
	case []any:
		return "a list"
	case string:
		return "a string"
	case []byte:
		return "bytes"
	case bool:
		return "a boolean"
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64, vcvalue.Int128, vcvalue.Uint128, float32, float64:
		return "a number"
	case vcvalue.Date:
		return "a date"
	case vcvalue.Timestamp:
		return "a timestamp"
	case vcvalue.Decimal:
		return "a decimal"
	case vcvalue.UUID:
		return "a UUID"
	default:
		return "a single value"
	}
}

// BadAnswer is the error for a guest export's answer this module cannot
// read: ErrInternal, naming the export and what was wrong with the answer.
// The caller's input is not at fault. The answer's shape is a contract
// between the guest and this module, so a bad one is a bug, or a guest that
// does not match this module's version, such as a guest built from other
// source than the module that embeds it.
func BadAnswer(export string, problem error) error {
	return fmt.Errorf("%w: the guest's answer to %s does not read: %v; this is a bug, or a guest that does not match this module's version", ErrInternal, export, problem)
}
