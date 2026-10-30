package encrypt

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
)

// Path is one ordered member of the elements of an array in a JSONSearch
// field, for the element match: the generated
// Fields.<Field>.Elements.<Array>.Match. Read one from the generated
// Paths, which names each ordered member as the JSON nests it:
// Paths.Profile.Visits.Place is the member place of each element of
// $.visits[*].
//
// E is the array: a type the generator writes for each array, which the
// array's Match takes predicates of. T is the member's Go type in the
// document's struct, or any when the generator cannot name one (a
// json.RawMessage document, say). Pass a Path to [AtPath] for a predicate.
type Path[E, T any] struct {
	array  string
	member string
}

// NewPath is the Path of member below array: for generated code. A
// program reads its paths from the generated Paths, or names a member at
// run time with the generated array accessor's Member.
func NewPath[E, T any](array, member string) Path[E, T] {
	return Path[E, T]{array: array, member: member}
}

// String is the member's full path: $.visits[*].place.
func (p Path[E, T]) String() string {
	if p.member == "" {
		return p.array
	}
	return p.array + "." + p.member
}

// AtPath is the comparisons of the member at p, for the element match.
// Each returns an [ElementPredicate] of p's array, so only that array's
// Match takes it, and each takes a value of the member's Go type:
//
//	encrypt.AtPath(Paths.Profile.Visits.At).Gt(15)
//
// AtPath is a function, not a method of Path, because a Go method cannot
// take type parameters of its own.
func AtPath[E, T any](p Path[E, T]) MemberTest[E, T] {
	return MemberTest[E, T]{member: p.member}
}

// MemberTest makes the predicates on one member of an array's elements.
// Make one with [AtPath], or with the generated array accessor's Member for
// a member named at run time, whose T is any.
//
// Each comparison is of the member's ordering term, as the orderings at a
// path compare: numbers order as float64, so integers past 2^53 can tie,
// and text orders case- and accent-folded. Equality is both inclusive
// bounds at one value, so [MemberTest.Eq] is an equality of those folded
// values.
//
// A value is a Go number or string, or a json.RawMessage of JSON text,
// written to JSON as the orderings at a path write theirs. It is
// plaintext: an ElementPredicate prints and logs its member and comparison,
// and never its values. A predicate copies the bytes of a json.RawMessage
// or a []byte value, so changing the caller's bytes does not change it. A
// value of any other reference type, such as a map, a slice or a pointer,
// is not copied: changing what it refers to changes the predicate.
type MemberTest[E, T any] struct {
	member string
}

// Eq is the test that the member equals v, compared by its ordering term:
// text is case- and accent-folded, so "sibling" equals "Sibling", and
// integers past 2^53 can tie. For an exact equality of one member, use the
// field's EqAt at the member's full path, which any element can answer.
func (m MemberTest[E, T]) Eq(v T) ElementPredicate[E] { return m.predicate("eq", v) }

// Lt is the test that the member is less than v.
func (m MemberTest[E, T]) Lt(v T) ElementPredicate[E] { return m.predicate("lt", v) }

// Lte is the test that the member is at most v.
func (m MemberTest[E, T]) Lte(v T) ElementPredicate[E] { return m.predicate("lte", v) }

// Gt is the test that the member is greater than v.
func (m MemberTest[E, T]) Gt(v T) ElementPredicate[E] { return m.predicate("gt", v) }

// Gte is the test that the member is at least v.
func (m MemberTest[E, T]) Gte(v T) ElementPredicate[E] { return m.predicate("gte", v) }

// Between is the test that the member is from lo to hi, inclusive.
func (m MemberTest[E, T]) Between(lo, hi T) ElementPredicate[E] {
	return ElementPredicate[E]{member: m.member, op: "between", values: []any{detached(lo), detached(hi)}}
}

func (m MemberTest[E, T]) predicate(op string, v T) ElementPredicate[E] {
	return ElementPredicate[E]{member: m.member, op: op, values: []any{detached(v)}}
}

// ElementPredicate is one test on a member of the elements of the array E,
// for that array's generated Match. Make one with [AtPath], or with the
// generated array accessor's Member.
//
// Its member names one field of each element, relative to the element:
// relationship, or address.city, written as the field's ordered path is
// written below the array. Its full path must be one the field orders.
type ElementPredicate[E any] struct {
	member string
	op     string
	values []any
}

// Member is the member the predicate tests, relative to an element.
func (p ElementPredicate[E]) Member() string { return p.member }

// Op is the comparison, as the engine names it: eq, lt, lte, gt, gte or
// between; "" for a zero ElementPredicate.
func (p ElementPredicate[E]) Op() string { return p.op }

// Values are a copy of the predicate's values: one, or for between the
// low bound then the high. They are the plaintext the caller gave. The
// slice and the bytes of a json.RawMessage or []byte in it are copies, so
// changing them does not change the predicate; a value of another
// reference type is the caller's own. For generated code.
func (p ElementPredicate[E]) Values() []any {
	values := slices.Clone(p.values)
	for i, v := range values {
		values[i] = detached(v)
	}
	return values
}

// detached is v with the bytes of a json.RawMessage or a []byte copied, so
// the copy shares no bytes with v. Any other value is returned as it is.
func detached(v any) any {
	switch b := v.(type) {
	case json.RawMessage:
		return slices.Clone(b)
	case []byte:
		return slices.Clone(b)
	}
	return v
}

// String names the member and the comparison, and hides the values.
func (p ElementPredicate[E]) String() string {
	if p.op == "" {
		return "encrypt.ElementPredicate{}"
	}
	return fmt.Sprintf("encrypt.ElementPredicate{member: %q, op: %s, values: %s}", p.member, p.op, redacted)
}

// GoString is what %#v prints: [ElementPredicate.String].
func (p ElementPredicate[E]) GoString() string { return p.String() }

// Format prints [ElementPredicate.String] for every verb fmt hands it.
func (p ElementPredicate[E]) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// LogValue is what slog records: the member and the comparison, and
// [redacted] for the values.
func (p ElementPredicate[E]) LogValue() slog.Value {
	return slog.GroupValue(slog.String("member", p.member), slog.String("op", p.op), slog.String("values", redacted))
}
