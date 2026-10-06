package encrypt

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
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
// `nonempty!("..")` literal binds. [Context.With] extends it as
// Rust's NonEmpty::with does: the result is the two-element list
// [previous, part], nesting to the left. So NewContext("users").With("age")
// is the pair a Rust `struct = .., context = "users"` derive binds its `age`
// field under — and what ParseLabel("users/age") binds — rendering the ZeroKMS
// descriptor users/age; extended With(uint64(7)) it is what a row sealed
// with the chain's .extend(7u64) binds for that field.
// A one-element list is not the bare part, and this type cannot spell one.
//
// Not every Context is a planned field's. A probe ([Cipher.Term]) takes any
// Context, in whatever shape the data was sealed under. A field of a record
// plan ([FieldPlan.Context]) binds a [Label] of at least two plain segments
// and nothing else — the guest lowers a plan into one context per record
// with one identity per field, and refuses any other shape — so [NewPlan]
// and [PlanFromTags] refuse a one-part context, a one-segment label and an
// extended context at construction. A record call extends every field's
// label alike with [ExtendContext].
//
// A Context owns its parts: a byte-slice part is copied in, so a caller's
// buffer reused once the Context is built does not change it.
//
// Compare two Contexts with [Context.Equal]. Do not use == and do not use a
// Context as a map key: a list context holds a slice, and Go panics when it
// compares those.
type Context struct {
	node any
}

// NewContext makes a one-part context, for a probe ([Cipher.Term]) against
// data sealed under one part, or as the base [Context.With] extends. It is
// not a planned field's context: a field binds a [Label] of two or more
// segments ([ParseLabel]), and [NewPlan] refuses a one-part context with the
// field named. The part must not be empty: a bare
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
// otherwise, an empty part included. For string literals in probes.
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
		return Context{}, fmt.Errorf("encrypt: cannot extend an empty context")
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

// fieldLabel is the context a planned field may bind, as the guest's
// lowering reads it: a label of at least two plain segments and nothing
// else, returned as that Label. A one-part context, an extended context and
// a part that is not text are refused with a reason that says what is
// accepted; a flat list of plain text parts is the label it spells,
// whichever constructor built it.
func (c Context) fieldLabel() (Label, error) {
	parts, ok := c.node.([]any)
	if !ok {
		return Label{}, errors.New(`is one part, not a label; a planned field binds a label of at least two plain segments, ParseLabel("table/column").Context()`)
	}
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		s, ok := part.(string)
		if !ok {
			return Label{}, errors.New("is extended, or holds a part that is not text; a planned field binds a plain label, and a record call extends every field's label alike with ExtendContext")
		}
		segments = append(segments, s)
	}
	if len(segments) < 2 {
		return Label{}, errors.New("has one segment; a planned field binds a label of at least two")
	}
	l, err := NewLabel(segments...)
	if err != nil {
		return Label{}, fmt.Errorf("is not a plain label: %w", err)
	}
	return l, nil
}

// checkRootNonEmpty refuses the bare parts that are themselves an empty
// context. Integers never are, whatever their value.
func checkRootNonEmpty(part any) error {
	switch p := part.(type) {
	case string:
		if p == "" {
			return errors.New("encrypt: an empty string is an empty context")
		}
	case []byte:
		if len(p) == 0 {
			return errors.New("encrypt: an empty byte slice is an empty context")
		}
	}
	return nil
}

func checkPart(part any) error {
	switch part.(type) {
	case string, []byte, int32, int64, uint32, uint64, int:
		return nil
	default:
		return fmt.Errorf("encrypt: %T is not a context part (string, []byte or integer)", part)
	}
}

// Equal reports whether c and other are the same context: the same parts,
// in the same order, with the same types, so a probe built from one matches
// terms written under the other. This is the supported comparison; == on
// two Contexts panics when either holds a list.
func (c Context) Equal(other Context) bool { return reflect.DeepEqual(c.node, other.node) }

// isZero reports whether c is the zero Context, which binds nothing: what a
// plan field without a context, or a zero Label, carries.
func (c Context) isZero() bool { return c.node == nil }

// flatContext is the context a [Label] binds: one segment is the bare part,
// as NewContext makes it; two or more are a flat list of the segments. The
// segments are plain by construction, so no part check is needed, and a
// list is never built from one part (a one-element list is a different
// context from the bare part, and this type cannot spell one).
func flatContext(segments []string) Context {
	switch len(segments) {
	case 0:
		return Context{}
	case 1:
		return Context{node: segments[0]}
	}
	parts := make([]any, len(segments))
	for i, s := range segments {
		parts[i] = s
	}
	return Context{node: parts}
}
