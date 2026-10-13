package stashgen

import (
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// A struct that names an EQL type beside a context_field has no table of
// its own to store the EQL value under: the lowering refuses it, naming the
// field, as the engine would.
func TestLoweringRefusesAnEQLTypeBesideAContextField(t *testing.T) {
	eql := []EQLType{{Name: "TextEq", Plaintext: KindString, Indexes: []IndexName{IndexEquality}, Query: "TextEqQuery", Producible: true}}
	text := GoType{Name: "string", Kind: KindString, Basic: "string"}
	d := Declaration{Type: "Note", ContextField: "tenant", Fields: []Field{
		{Name: "tenant", GoName: "Tenant", GoType: text, Verb: VerbContextField},
		{Name: "email", GoName: "Email", GoType: text, Verb: VerbEncryptInto, EQLType: "TextEq"},
	}}
	_, err := lowerDeclaration(d, eql)
	fe, ok := err.(*FieldError)
	if !ok || fe.Field != "Email" || !strings.Contains(fe.Reason, "has no table of its own") {
		t.Fatalf("lowerDeclaration = %v, want a FieldError on Email about the table", err)
	}
	// Without the EQL type the context field lowers: no context, the
	// field's name as the plan's context field, and the sealed field alone.
	d.Fields[1] = Field{Name: "email", GoName: "Email", GoType: text, Verb: VerbEncrypt}
	plan, err := lowerDeclaration(d, eql)
	if err != nil || plan.ContextField != "tenant" || len(plan.Context) != 0 || len(plan.Fields) != 1 {
		t.Fatalf("lowerDeclaration = %+v, %v", plan, err)
	}
}

// An EQL type seals one width of its kind. A Go field of the same kind and
// another width is refused here, naming both, rather than by the engine's
// generic refusal; a narrower integer that seals as the type's width passes.
func TestLoweringRefusesAnotherWidthOfTheKind(t *testing.T) {
	eql := []EQLType{
		{Name: "Integer", Plaintext: KindInt, Producible: true, wire: record.Int32},
		{Name: "Bigint", Plaintext: KindInt, Producible: true, wire: record.Int64},
		{Name: "Real", Plaintext: KindFloat, Producible: true, wire: record.Float32},
		{Name: "Double", Plaintext: KindFloat, Producible: true, wire: record.Float64},
	}
	field := func(basic string, kind Kind, eqlType string) Declaration {
		return Declaration{Type: "Row", Context: "rows", Fields: []Field{
			{Name: "v", GoName: "V", GoType: GoType{Name: basic, Kind: kind, Basic: basic}, Verb: VerbEncryptInto, EQLType: eqlType},
		}}
	}
	for _, c := range []struct {
		basic, eqlType, want string
		kind                 Kind
	}{
		{"int", "Integer", "Integer seals int32, and int seals as int64", KindInt},
		{"int64", "Integer", "Integer seals int32, and int64 seals as int64", KindInt},
		{"int32", "Bigint", "Bigint seals int64, and int32 seals as int32", KindInt},
		{"float64", "Real", "Real seals float32, and float64 seals as float64", KindFloat},
		{"float32", "Double", "Double seals float64, and float32 seals as float32", KindFloat},
	} {
		_, err := lowerDeclaration(field(c.basic, c.kind, c.eqlType), eql)
		fe, ok := err.(*FieldError)
		if !ok || fe.Field != "V" || fe.Reason != c.want {
			t.Errorf("%s into %s: lowerDeclaration = %v, want %q", c.basic, c.eqlType, err, c.want)
		}
	}
	for _, c := range []struct {
		basic, eqlType string
		kind           Kind
	}{
		{"int32", "Integer", KindInt}, {"int16", "Integer", KindInt}, {"int8", "Integer", KindInt},
		{"int64", "Bigint", KindInt}, {"int", "Bigint", KindInt},
		{"float32", "Real", KindFloat}, {"float64", "Double", KindFloat},
	} {
		if _, err := lowerDeclaration(field(c.basic, c.kind, c.eqlType), eql); err != nil {
			t.Errorf("%s into %s: %v", c.basic, c.eqlType, err)
		}
	}
}
