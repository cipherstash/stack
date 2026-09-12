package stackencrypt

import "fmt"

// Context is the encryption context a record field or a term probe binds:
// a domain-separating value that becomes both the ciphertext's AAD (and
// the ZeroKMS descriptor the data key is bound to) and the index terms'
// PRF context. Contexts are identities, so a probe must spell the context
// in exactly the shape the field was sealed under.
//
// A Context is a part or a list of parts. A part is a string, a byte slice
// or an integer (int32, int64, uint32, uint64; Go's int is sent as int64).
// [NewContext] makes a one-part context — the bare part, the shape a Rust
// `#[derive(EncryptFrom)]` field is sealed under when the caller supplies no
// context of its own. [Context.With] extends it as Rust's NonEmpty::with
// does: the result is the two-element list [previous, part], nesting to the
// left, so NewContext("users/age").With(uint64(7)) is the context a row
// sealed with encrypt_into_with_context(row, 7u64) binds for that field.
// A one-element list is not the bare part, and this type cannot spell one.
type Context struct {
	node any
}

// NewContext makes a one-part context.
func NewContext(part any) (Context, error) {
	if err := checkPart(part); err != nil {
		return Context{}, err
	}
	return Context{node: part}, nil
}

// MustContext is [NewContext] for a part known to be valid; it panics
// otherwise. For string literals in plans and probes.
func MustContext(part any) Context {
	c, err := NewContext(part)
	if err != nil {
		panic(err)
	}
	return c
}

// With extends the context by one part, nesting to the left.
func (c Context) With(part any) (Context, error) {
	if c.node == nil {
		return Context{}, fmt.Errorf("stackencrypt: cannot extend an empty context")
	}
	if err := checkPart(part); err != nil {
		return Context{}, err
	}
	return Context{node: []any{c.node, part}}, nil
}

// value renders the context in the guest's grammar: a scalar or nested
// lists of scalars, ready for the transport codec.
func (c Context) value() any { return c.node }

func checkPart(part any) error {
	switch part.(type) {
	case string, []byte, int32, int64, uint32, uint64, int:
		return nil
	default:
		return fmt.Errorf("stackencrypt: %T is not a context part (string, []byte or integer)", part)
	}
}
