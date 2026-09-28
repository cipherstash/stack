package plan

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode"
)

// Fact is what the SDK knows about one field of a message: where it is,
// what it is, and the annotations the domain schema put on it. It is
// source-agnostic. A [Source] makes facts from something that describes a
// message (a protobuf descriptor, a Go struct type); a policy reads them
// and never learns where they came from.
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
// given: a struct value or pointer for [StructTags], a proto.Message for a
// protobuf source. Facts are returned in field order.
type Source interface {
	Facts(msg any) ([]Fact, error)
}

// SourceFunc adapts a function to a [Source].
type SourceFunc func(msg any) ([]Fact, error)

// Facts calls f.
func (f SourceFunc) Facts(msg any) ([]Fact, error) { return f(msg) }

// StructTags is the Go-struct fact source: one fact per exported, direct
// field of a struct (msg is a struct value or a pointer to one), with the
// annotations its `facts` tag lists:
//
//	type Individual struct {
//	    ID         int64
//	    Email      string `facts:"fides.data_categories=user.contact.email"`
//	    MedicareNo string `facts:"fides.data_categories=user.government_id,user.financial"`
//	}
//
// The tag is `key=value[,value...]`, repeated with `;` for more keys.
// GoField is the Go field name and Field is its snake_case ("MedicareNo"
// is "medicare_no", "ID" is "id", "HTTPPort" is "http_port"): the name a
// proto field or a database column would have, so the column identity a
// field binds by default is the one the Rust derive and the schema spell.
// Number is 0 and Kind is the field's reflect.Kind (through one pointer).
//
// Unexported and embedded fields are not facts: a plan binds exported,
// direct fields only. A `facts` tag on one — or on any field of an
// embedded struct — is an error, not a field quietly left in plaintext.
var StructTags Source = SourceFunc(structFacts)

func structFacts(msg any) ([]Fact, error) {
	t := reflect.TypeOf(msg)
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("plan: StructTags reads structs, not %T", msg)
	}
	facts := make([]Fact, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() || sf.Anonymous {
			if err := refuseUnbindableTag(sf); err != nil {
				return nil, fmt.Errorf("plan: %s.%s: %w", t, sf.Name, err)
			}
			continue
		}
		kind := sf.Type
		if kind.Kind() == reflect.Pointer {
			kind = kind.Elem()
		}
		annotations, err := parseFactsTag(sf.Tag.Get("facts"))
		if err != nil {
			return nil, fmt.Errorf("plan: %s.%s: %w", t, sf.Name, err)
		}
		facts = append(facts, Fact{
			Message:     t.String(),
			Field:       snakeCase(sf.Name),
			GoField:     sf.Name,
			Kind:        kind.Kind().String(),
			Annotations: annotations,
		})
	}
	return facts, nil
}

// refuseUnbindableTag is the error for a `facts` tag on a field a plan
// cannot bind: an unexported or embedded field, or any field of an
// embedded struct, however deep. The tag says the field is classified;
// dropping it would store the field in plaintext with no rule ever asked.
func refuseUnbindableTag(sf reflect.StructField) error {
	if sf.Tag.Get("facts") != "" {
		if sf.Anonymous {
			return errors.New("a facts tag on an embedded field, which a plan cannot bind")
		}
		return errors.New("a facts tag on an unexported field, which a plan cannot bind")
	}
	if !sf.Anonymous {
		return nil
	}
	if tagged := firstFactsTag(sf.Type); tagged != "" {
		return fmt.Errorf("embedded %s has a facts tag on %s, which a plan cannot bind; make it a direct field", sf.Type, tagged)
	}
	return nil
}

// firstFactsTag names the first field of t (a struct, through one
// pointer), or of a struct embedded in it, that carries a facts tag; ""
// when none does.
func firstFactsTag(t reflect.Type) string {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return ""
	}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if sf.Tag.Get("facts") != "" {
			return sf.Name
		}
		if sf.Anonymous {
			if name := firstFactsTag(sf.Type); name != "" {
				return sf.Name + "." + name
			}
		}
	}
	return ""
}

// snakeCase is a Go field name as a schema would spell it: a lower-case
// word per hump, joined by underscores, with an initialism kept as one
// word ("HTTPPort" is "http_port", "ID" is "id"). Digits stay with the
// word before them ("Line2" is "line2").
func snakeCase(name string) string {
	runes := []rune(name)
	var b strings.Builder
	b.Grow(len(name) + 4)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func parseFactsTag(tag string) ([]Annotation, error) {
	if tag == "" {
		return nil, nil
	}
	var out []Annotation
	for _, part := range strings.Split(tag, ";") {
		key, values, ok := strings.Cut(part, "=")
		if !ok || key == "" || values == "" {
			return nil, fmt.Errorf("facts tag %q: want key=value[,value...]", part)
		}
		if slices.ContainsFunc(out, func(a Annotation) bool { return a.Key == key }) {
			return nil, fmt.Errorf("facts tag: key %q given twice", key)
		}
		vs := strings.Split(values, ",")
		if slices.Contains(vs, "") {
			return nil, errors.New("facts tag: empty value for " + key)
		}
		out = append(out, Annotation{Key: key, Values: vs})
	}
	return out, nil
}
