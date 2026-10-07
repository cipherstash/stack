package stashgen

import (
	"strings"
	"testing"
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
