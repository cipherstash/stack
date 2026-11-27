package guest

import "github.com/cipherstash/vitaminc/bindings/go/vcvalue"

// WipeDecoded zeroes every []byte in a value vcffi.Unmarshal returned: the
// bytes at its top level, in a list ([]any) and in an object
// (vcvalue.Object), at any depth. Unmarshal gives every bytes leaf its own
// copy, so a decoder that refuses a frame calls it on the whole decoded
// value before it returns: what it had not read yet, or had read and then
// refused, can hold a credential too. Text and numbers are left as they are:
// a Go string cannot be wiped.
func WipeDecoded(v any) {
	switch v := v.(type) {
	case []byte:
		Wipe(v)
	case []any:
		for _, item := range v {
			WipeDecoded(item)
		}
	case vcvalue.Object:
		for _, f := range v {
			WipeDecoded(f.Value)
		}
	}
}
