package stackencrypt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Label names the data a field or a probe binds: a table and a column
// ("users/email"), a document path ("documents/v2/body"), any name a direct
// consumer chooses. ZeroKMS binds the data key to that name and writes it in
// its log, spelled exactly as given. It is the Go form of Rust's
// stack_encrypt::Label; EQL's identifier, a table and a column, is a Label of
// two segments ([plan.Identifier]).
//
// # Naming and scoping
//
// A context carries two kinds of information, and each has one spelling:
//
//   - A name says WHAT the data is. Spell it as a Label.
//   - A scope says WHICH slice of that data: a tenant, a row. Spell it by
//     extending the name's context with [Context.With], or with the
//     [ExtendContext] option on a record call.
//
// In practice:
//
//	What you mean             Spelling                                                ZeroKMS log
//	the users.email column    label, _ := ParseLabel("users/email")                   users/email
//	that column, tenant 7     label.Context().With(uint64(7))                         (users/email)/7u64
//	a deeper name             ParseLabel("documents/v2/body")                         documents/v2/body
//	a one-part name           ParseLabel("users"), the same as NewContext("users")    users
//
// Do not build a name with With, and do not put a scope into a Label. The
// renderer keeps the two apart: a name is one flat list, a scope nests. So
// (users/email)/7u64 is never read as a three-segment name, and
// documents/v2/body is never read as a scoped column.
//
// A two-segment Label binds the same context a Rust
// `#[stash(struct = .., context = "<table>")]` derive gives a field. That is
// what lets a Go label open a row a Rust derive wrote, and a probe built from
// the label match the terms the derive produced.
//
// # Segments
//
// Every segment is plain — non-empty, no control or invisible format
// characters (zero-width and bidirectional marks), none of '/', '(' or ')',
// not beginning with "b64:", a digit or '-' — which is exactly
// the text the descriptor renders verbatim. So a Label's [Label.String] is
// its descriptor, [ParseLabel] reads that string back losslessly (no
// segment can contain the separator), and a string that is not a label is
// refused with a [LabelError] naming the segment, never escaped silently.
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

// Segments returns the label's segments, in order; at least one.
func (l Label) Segments() []string { return slices.Clone(l.segments) }

// String renders the label as its descriptor: the segments joined by '/'.
func (l Label) String() string { return strings.Join(l.segments, labelSeparator) }

// Context is the label as the context a field or probe binds. A zero
// Label gives the zero Context, which every call refuses as "needs a
// context".
func (l Label) Context() Context { return flatContext(l.segments) }

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
			return &LabelError{Index: index, Reason: "contains '/', the separator"}
		}
		if unicode.IsControl(r) || r == '(' || r == ')' {
			return &LabelError{Index: index, Reason: fmt.Sprintf("contains %q, which the descriptor reserves", r)}
		}
		if strings.ContainsRune(invisible, r) {
			return &LabelError{Index: index, Reason: fmt.Sprintf("contains %q, an invisible format character", r)}
		}
	}
	return nil
}

// invisible is the format characters with no glyph of their own: the soft
// hyphen, the Arabic letter mark, the Mongolian vowel separator, the
// zero-width characters, the bidirectional embeddings, overrides and
// isolates, and the byte-order mark. unicode.IsControl covers only Cc;
// these are Cf. A name containing one prints like another name in the
// ZeroKMS log, so they are refused beside the control characters. The same
// list as Rust's Label::INVISIBLE; the shared fixture holds the two together.
const invisible = "\u00ad\u061c\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff"
