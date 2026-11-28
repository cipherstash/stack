package guest

import "github.com/cipherstash/stack/languages/golang/internal/frame"

// WipeDecoded sets to zero every []byte in a value that frame.Unmarshal
// returned. That covers bytes at the top level, in a list ([]any), and in an
// object (frame.Object), at any depth.
//
// Unmarshal gives every bytes value a copy of its own. A decoder that
// refuses a frame therefore calls WipeDecoded on the whole decoded value
// before it returns. The parts that the decoder had not read yet can contain
// a credential. So can the parts that it read and then refused.
//
// WipeDecoded leaves text and numbers unchanged, because a Go string cannot
// be wiped.
func WipeDecoded(v any) {
	switch v := v.(type) {
	case []byte:
		Wipe(v)
	case []any:
		for _, item := range v {
			WipeDecoded(item)
		}
	case frame.Object:
		for _, f := range v {
			WipeDecoded(f.Value)
		}
	}
}
