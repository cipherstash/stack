package stackencrypt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Label is a path of plain segments: how a direct consumer names the data
// it keys — "users/email", "documents/v2/body" — and the one context whose
// ZeroKMS descriptor is the string it is written as. It is the Go form of
// Rust's stack_encrypt::Label; EQL's identifier, a table and a column, is
// the same shape with exactly two segments ([plan.Identifier]).
//
// Every segment is plain — non-empty, no control characters, none of '/',
// '(' or ')', not beginning with "b64:", a digit or '-' — which is exactly
// the text the descriptor renders verbatim. So a Label's [Label.String] is
// its descriptor, [ParseLabel] reads that string back losslessly (no
// segment can contain the separator), and a string that is not a label is
// refused with a [LabelError] naming the segment, never escaped silently.
//
// As a context ([Label.Context]): one segment is the bare part, the same
// context as NewContext(segment) and a Rust `#[stash(context = "..")]`
// literal; two are the pair NewContext(table).With(column), what a Rust
// `struct = .., context = "<table>"` derive binds; three or more are a flat
// list, a/b/c, which the nesting With chain ((a/b)/c) is not.
type Label struct {
	segments []string
}

// labelSeparator joins a label's segments: the descriptor's own separator.
const labelSeparator = "/"

// NewLabel makes a label from its segments, each checked to be plain.
func NewLabel(segments ...string) (Label, error) {
	if len(segments) == 0 {
		return Label{}, ErrEmptyLabel
	}
	for i, s := range segments {
		if err := checkSegment(i, s); err != nil {
			return Label{}, err
		}
	}
	return Label{segments: slices.Clone(segments)}, nil
}

// ParseLabel reads a label from its rendered form, segments separated by
// '/': the inverse of [Label.String]. "users//email" and "users/" are
// refused (an empty segment), as is "" (one empty segment).
func ParseLabel(s string) (Label, error) {
	return NewLabel(strings.Split(s, labelSeparator)...)
}

// MustLabel is [ParseLabel] for a label known to be valid; it panics
// otherwise. For string literals in plans and probes:
//
//	email := stackencrypt.MustLabel("users/email")
//	probe, err := cipher.Term(ctx, "bob@example.com", email.Context(), stackencrypt.Equality)
func MustLabel(s string) Label {
	l, err := ParseLabel(s)
	if err != nil {
		panic(err)
	}
	return l
}

// Segments returns the label's segments, in order; at least one.
func (l Label) Segments() []string { return slices.Clone(l.segments) }

// String renders the label as its descriptor: the segments joined by '/'.
func (l Label) String() string { return strings.Join(l.segments, labelSeparator) }

// Context is the label as the context a field or probe binds. A zero
// Label gives the zero Context, which every call refuses as "needs a
// context".
func (l Label) Context() Context {
	switch len(l.segments) {
	case 0:
		return Context{}
	case 1:
		return Context{node: l.segments[0]}
	}
	parts := make([]any, len(l.segments))
	for i, s := range l.segments {
		parts[i] = s
	}
	return Context{node: parts}
}

// ErrEmptyLabel is [NewLabel]'s refusal of no segments at all.
var ErrEmptyLabel = errors.New("stackencrypt: a label needs at least one segment")

// LabelError says why a string is not a [Label] segment. Index is the
// segment's position, counting from zero.
type LabelError struct {
	Index  int
	Reason string
}

func (e *LabelError) Error() string {
	return fmt.Sprintf("stackencrypt: label segment %d %s", e.Index, e.Reason)
}

// checkSegment is the one definition of plain text, the same as Rust's
// Label::check_segment: what passes here is what the descriptor renders
// verbatim.
func checkSegment(index int, s string) error {
	if s == "" {
		return &LabelError{Index: index, Reason: "is empty"}
	}
	if strings.HasPrefix(s, "b64:") || s[0] == '-' || (s[0] >= '0' && s[0] <= '9') {
		return &LabelError{Index: index, Reason: "begins like another descriptor form (b64:, a digit or -)"}
	}
	for _, r := range s {
		if r == '/' {
			return &LabelError{Index: index, Reason: "contains the separator '/'"}
		}
		if unicode.IsControl(r) || r == '(' || r == ')' {
			return &LabelError{Index: index, Reason: fmt.Sprintf("contains %q, which the descriptor reserves", r)}
		}
	}
	return nil
}
