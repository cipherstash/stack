package stackencrypt

import (
	"bytes"
	"errors"
	"fmt"
)

// Context is the encryption context a record field or a term probe binds:
// a domain-separating value that becomes both the ciphertext's AAD (and
// the ZeroKMS descriptor the data key is bound to) and the index terms'
// PRF context. Contexts are identities, so a probe must spell the context
// in exactly the shape the field was sealed under.
//
// A Context is a part or a list of parts. A part is a string, a byte slice
// or an integer (int32, int64, uint32, uint64; Go's int is sent as int64).
// [NewContext] makes a one-part context — the bare part, what a Rust
// `#[stash(context = "..")]` literal binds. [Context.With] extends it as
// Rust's NonEmpty::with does: the result is the two-element list
// [previous, part], nesting to the left. So NewContext("users").With("age")
// is the pair a Rust `struct = .., context = "users"` derive binds its `age`
// field under — and MustLabel("users/age").Context() — rendering the ZeroKMS
// descriptor users/age; extended With(uint64(7)) it is what a row sealed
// with encrypt_into_with_context(row, 7u64) binds for that field.
// A one-element list is not the bare part, and this type cannot spell one.
//
// A Context owns its parts: a byte-slice part is copied in, so a caller's
// buffer reused once the Context is built does not change it.
type Context struct {
	node any
}

// NewContext makes a one-part context. The part must not be empty: a bare
// empty string or empty byte slice is an empty context, and the guest
// proves every context non-empty at the boundary, so such a Context could
// only ever fail — every call, with ErrEncoding. Rust refuses the same
// thing one step earlier: nonempty!("") does not compile.
//
// Emptiness is the whole tree's property, not the part's — a list is empty
// only when every part is — so [Context.With] may still add an empty part
// to a context that already has a non-empty one. Only the root is checked
// here.
func NewContext(part any) (Context, error) {
	if err := checkPart(part); err != nil {
		return Context{}, err
	}
	if err := checkRootNonEmpty(part); err != nil {
		return Context{}, err
	}
	return Context{node: ownPart(part)}, nil
}

// MustContext is [NewContext] for a part known to be valid; it panics
// otherwise, an empty part included. For string literals in plans and
// probes.
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
	return Context{node: []any{c.node, ownPart(part)}}, nil
}

// ownPart is part as a context stores it: a byte slice is copied, so
// neither a Context nor an option that extends one ([ExtendContext])
// aliases a caller's buffer. Every other part type is a value.
func ownPart(part any) any {
	if b, ok := part.([]byte); ok {
		return bytes.Clone(b)
	}
	return part
}

// value renders the context in the guest's grammar: a scalar or nested
// lists of scalars, ready for the transport codec.
func (c Context) value() any { return c.node }

// checkRootNonEmpty refuses the bare parts that are themselves an empty
// context. Integers never are, whatever their value.
func checkRootNonEmpty(part any) error {
	switch p := part.(type) {
	case string:
		if p == "" {
			return errors.New("stackencrypt: an empty string is an empty context")
		}
	case []byte:
		if len(p) == 0 {
			return errors.New("stackencrypt: an empty byte slice is an empty context")
		}
	}
	return nil
}

func checkPart(part any) error {
	switch part.(type) {
	case string, []byte, int32, int64, uint32, uint64, int:
		return nil
	default:
		return fmt.Errorf("stackencrypt: %T is not a context part (string, []byte or integer)", part)
	}
}
