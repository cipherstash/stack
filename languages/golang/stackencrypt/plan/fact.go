package plan

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Fact is what the SDK knows about one field of a message: where it is,
// what it is, and the annotations the domain schema put on it. It is
// source-agnostic. A [Source] makes facts from something that describes a
// message (a protobuf descriptor, a Go struct type); a policy reads them
// and never learns where they came from.
type Fact struct {
	// Message is the message's (or struct's) full name, for errors.
	Message string
	// Field is the field's schema name: the proto field name, or the Go
	// field name for a struct. It is the column a field encrypts into
	// unless a rule pins another ([Column]).
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

// goField is the Go struct field the fact binds to.
func (f Fact) goField() string {
	if f.GoField != "" {
		return f.GoField
	}
	return f.Field
}

// String names the field and its annotations, the way errors name them.
func (f Fact) String() string {
	var b strings.Builder
	if f.Message != "" {
		b.WriteString(f.Message)
		b.WriteByte('.')
	}
	b.WriteString(f.Field)
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
// The tag is `key=value[,value...]`, repeated with `;` for more keys. Field
// and GoField are the Go field name, Number is 0 and Kind is the field's
// reflect.Kind (through one pointer). Unexported and embedded fields are
// skipped: a plan binds exported, direct fields only.
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
			Field:       sf.Name,
			GoField:     sf.Name,
			Kind:        kind.Kind().String(),
			Annotations: annotations,
		})
	}
	return facts, nil
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
