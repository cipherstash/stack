package plan

import (
	"fmt"
	"slices"
	"strings"
)

// Fact is what the SDK knows about one field of a message: where it is,
// what it is, and the annotations the domain schema put on it. It is
// source-agnostic. A [Source] makes facts from something that describes a
// message, such as a protobuf descriptor; a policy reads them and never
// learns where they came from.
type Fact struct {
	// Message is the message's (or struct's) full name, for errors.
	Message string
	// Field is the field's schema name: the proto field name, or, for a
	// struct, the Go field name in snake_case. It is the column a field
	// encrypts into unless a rule pins another ([Column]).
	Field string
	// GoField is the Go struct field the plan binds to. Field when empty.
	GoField string
	// Number is the proto field number; 0 when the source has none.
	Number int32
	// Kind is the field's kind in the source's own spelling ("string",
	// "int64", ...); informational, for rules that match on it.
	Kind string
	// Annotations are the facts proper: the domain schema's classification
	// of the field, such as its Fideslang data categories. A field with no
	// annotations is not the policy's concern unless a rule names it.
	Annotations []Annotation
}

// Annotation is one annotation on a field: a key and its values. For a
// protobuf extension the key is the extension's full name and the values
// are its (repeated) string values.
type Annotation struct {
	Key    string
	Values []string
}

// Values returns the values of every annotation on the field under key,
// in order.
func (f Fact) Values(key string) []string {
	var out []string
	for _, a := range f.Annotations {
		if a.Key == key {
			out = append(out, a.Values...)
		}
	}
	return out
}

// hasValue reports whether any value under key satisfies pred, without
// collecting the values: the matchers run once per rule per field.
func (f Fact) hasValue(key string, pred func(string) bool) bool {
	for _, a := range f.Annotations {
		if a.Key != key {
			continue
		}
		if slices.ContainsFunc(a.Values, pred) {
			return true
		}
	}
	return false
}

// goField is the Go struct field the fact binds to.
func (f Fact) goField() string {
	if f.GoField != "" {
		return f.GoField
	}
	return f.Field
}

// String names the field — and the Go field it binds to, when that is
// spelled differently — and its annotations, the way errors name them.
func (f Fact) String() string {
	var b strings.Builder
	if f.Message != "" {
		b.WriteString(f.Message)
		b.WriteByte('.')
	}
	b.WriteString(f.Field)
	if f.GoField != "" && f.GoField != f.Field {
		b.WriteString(" (")
		b.WriteString(f.GoField)
		b.WriteByte(')')
	}
	if len(f.Annotations) > 0 {
		b.WriteString(" [")
		for i, a := range f.Annotations {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s=%s", a.Key, strings.Join(a.Values, ","))
		}
		b.WriteByte(']')
	}
	return b.String()
}

// Source makes the facts for a message. msg is whatever [ForMessage] was
// given, such as a proto.Message for the protobuf source planned in
// CIP-4088. Facts are returned in field order.
type Source interface {
	Facts(msg any) ([]Fact, error)
}

// SourceFunc adapts a function to a [Source].
type SourceFunc func(msg any) ([]Fact, error)

// Facts calls f.
func (f SourceFunc) Facts(msg any) ([]Fact, error) { return f(msg) }
