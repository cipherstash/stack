package record

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

func users() *Plan {
	return &Plan{Context: []string{"users"}, Fields: []Field{
		{Name: "age", Kind: Uint32, Outputs: []Output{Ciphertext, Equality, Ore}},
		{Name: "email", Kind: String, Outputs: []Output{Ciphertext, Equality, Match}},
		{Name: "notes", Kind: String, Outputs: []Output{Ciphertext}},
	}}
}

func TestWireIsTheFixturesPlan(t *testing.T) {
	p := users()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	wire := p.Wire()
	want := vcvalue.Object{
		{Key: "age", Value: vcvalue.Object{
			{Key: "context", Value: []any{"users", "age"}},
			{Key: "outputs", Value: []any{"c", "eq", "ore"}},
			{Key: "type", Value: "uint32"},
		}},
		{Key: "email", Value: vcvalue.Object{
			{Key: "context", Value: []any{"users", "email"}},
			{Key: "outputs", Value: []any{"c", "eq", "match"}},
			{Key: "type", Value: "string"},
		}},
		{Key: "notes", Value: vcvalue.Object{
			{Key: "context", Value: []any{"users", "notes"}},
			{Key: "outputs", Value: []any{"c"}},
			{Key: "type", Value: "string"},
		}},
	}
	if !reflect.DeepEqual(wire, want) {
		t.Fatalf("Wire = %#v", wire)
	}
	if _, err := vcffi.Marshal(wire); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionNestsToTheLeftAndIdentityReplacesTheName(t *testing.T) {
	p := &Plan{Context: []string{"documents", "v2"}, Extension: []any{uint64(7), "eu"}, Fields: []Field{{Name: "medicare_number", Identity: "medicare_no", Outputs: []Output{Ciphertext}}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	got := p.FieldContext(p.Fields[0])
	want := []any{[]any{[]any{"documents", "v2", "medicare_no"}, uint64(7)}, "eu"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FieldContext = %#v", got)
	}
	if p.Descriptor(p.Fields[0]) != "documents/v2/medicare_no" {
		t.Fatalf("Descriptor = %q", p.Descriptor(p.Fields[0]))
	}
	// An untyped field carries no "type" key.
	if spec := p.Wire()[0].Value.(vcvalue.Object); len(spec) != 2 {
		t.Fatalf("untyped field spec = %#v", spec)
	}
	// A byte part is copied.
	buf := []byte("eu")
	q := &Plan{Context: []string{"a"}, Extension: []any{buf}, Fields: []Field{{Name: "f", Outputs: []Output{Ciphertext}}}}
	ctx := q.FieldContext(q.Fields[0])
	buf[0] = 'X'
	if string(ctx.([]any)[1].([]byte)) != "eu" {
		t.Fatal("the extension aliases the caller's buffer")
	}
}

func TestValidateRefusals(t *testing.T) {
	one := func(f Field) *Plan { return &Plan{Context: []string{"users"}, Fields: []Field{f}} }
	cases := map[string]*Plan{
		"no context":          {Fields: []Field{{Name: "a", Outputs: []Output{Ciphertext}}}},
		"bad segment":         {Context: []string{"users/x"}, Fields: []Field{{Name: "a", Outputs: []Output{Ciphertext}}}},
		"no field":            {Context: []string{"users"}},
		"no name":             one(Field{Outputs: []Output{Ciphertext}}),
		"name twice":          {Context: []string{"users"}, Fields: []Field{{Name: "a", Outputs: []Output{Ciphertext}}, {Name: "a", Outputs: []Output{Ciphertext}}}},
		"identity twice":      {Context: []string{"users"}, Fields: []Field{{Name: "a", Identity: "x", Outputs: []Output{Ciphertext}}, {Name: "b", Identity: "x", Outputs: []Output{Ciphertext}}}},
		"identity not plain":  one(Field{Name: "a", Identity: "1x", Outputs: []Output{Ciphertext}}),
		"unknown kind":        one(Field{Name: "a", Kind: "integer", Outputs: []Output{Ciphertext}}),
		"no output":           one(Field{Name: "a"}),
		"unknown output":      one(Field{Name: "a", Outputs: []Output{"json"}}),
		"output twice":        one(Field{Name: "a", Outputs: []Output{Equality, Equality}}),
		"bad extension part":  {Context: []string{"users"}, Extension: []any{1.5}, Fields: []Field{{Name: "a", Outputs: []Output{Ciphertext}}}},
		"name is not a label": one(Field{Name: "b64:x", Outputs: []Output{Ciphertext}}),
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseContext(t *testing.T) {
	got, err := ParseContext("documents/v2/body")
	if err != nil || !reflect.DeepEqual(got, []string{"documents", "v2", "body"}) {
		t.Fatalf("ParseContext = %v, %v", got, err)
	}
	for _, bad := range []string{"", "users/", "/users", "users//email", "b64:x", "1users", "-x", "a(b)", "a\u200bb"} {
		if _, err := ParseContext(bad); err == nil {
			t.Errorf("ParseContext(%q) accepted", bad)
		}
	}
	if err := CheckSegment("x/y"); err == nil || !strings.Contains(err.Error(), "separator") {
		t.Fatalf("CheckSegment: %v", err)
	}
}
