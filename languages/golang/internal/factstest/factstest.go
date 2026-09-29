// Package factstest is a test-only fact source for the plan package: Go
// struct fields annotated with a `facts` tag. The tag syntax is not API;
// real facts come from a schema, such as the protobuf source planned in
// CIP-4088. Internal, and imported only by _test files.
package factstest

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt/plan"
)

// StructTags is a Go-struct fact source for tests: one fact per exported,
// direct field of a struct (msg is a struct value or a pointer to one),
// with the annotations its `facts` tag lists:
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
var StructTags plan.Source = plan.SourceFunc(structFacts)

func structFacts(msg any) ([]plan.Fact, error) {
	t := reflect.TypeOf(msg)
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("factstest: StructTags reads structs, not %T", msg)
	}
	facts := make([]plan.Fact, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() || sf.Anonymous {
			if err := refuseUnbindableTag(sf); err != nil {
				return nil, fmt.Errorf("factstest: %s.%s: %w", t, sf.Name, err)
			}
			continue
		}
		kind := sf.Type
		if kind.Kind() == reflect.Pointer {
			kind = kind.Elem()
		}
		annotations, err := parseFactsTag(sf.Tag.Get("facts"))
		if err != nil {
			return nil, fmt.Errorf("factstest: %s.%s: %w", t, sf.Name, err)
		}
		facts = append(facts, plan.Fact{
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

func parseFactsTag(tag string) ([]plan.Annotation, error) {
	if tag == "" {
		return nil, nil
	}
	var out []plan.Annotation
	for _, part := range strings.Split(tag, ";") {
		key, values, ok := strings.Cut(part, "=")
		if !ok || key == "" || values == "" {
			return nil, fmt.Errorf("facts tag %q: want key=value[,value...]", part)
		}
		if slices.ContainsFunc(out, func(a plan.Annotation) bool { return a.Key == key }) {
			return nil, fmt.Errorf("facts tag: key %q given twice", key)
		}
		vs := strings.Split(values, ",")
		if slices.Contains(vs, "") {
			return nil, errors.New("facts tag: empty value for " + key)
		}
		out = append(out, plan.Annotation{Key: key, Values: vs})
	}
	return out, nil
}
