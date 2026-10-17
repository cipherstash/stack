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

// An EQL type seals one width of its kind. Any built-in integer type is
// sealed at the type's width (ADR-0002), and the plan names that width:
// gensupport converts each value, refusing one that does not fit. A 128-bit
// integer is not converted, and a float of the other width is refused here,
// naming both, rather than by the engine's generic refusal.
func TestLoweringWidensIntoAnEQLTypeAndRefusesWhatDoesNotConvert(t *testing.T) {
	eql := []EQLType{
		{Name: "Integer", Plaintext: KindInt, Producible: true, wire: record.Int32},
		{Name: "Bigint", Plaintext: KindInt, Producible: true, wire: record.Int64},
		{Name: "Real", Plaintext: KindFloat, Producible: true, wire: record.Float32},
		{Name: "Double", Plaintext: KindFloat, Producible: true, wire: record.Float64},
	}
	field := func(goType GoType, eqlType string) Declaration {
		return Declaration{Type: "Row", Context: "rows", Fields: []Field{
			{Name: "v", GoName: "V", GoType: goType, Verb: VerbEncryptInto, EQLType: eqlType},
		}}
	}
	basic := func(name string, kind Kind) GoType { return GoType{Name: name, Kind: kind, Basic: name} }
	for _, c := range []struct {
		goType        GoType
		eqlType, want string
	}{
		{GoType{Name: "encrypt.Int128", Kind: KindInt128}, "Bigint", "Bigint seals int64, and an encrypt.Int128 is not converted to it"},
		{GoType{Name: "encrypt.Uint128", Kind: KindUint128}, "Integer", "Integer seals int32, and an encrypt.Uint128 is not converted to it"},
		{basic("float64", KindFloat), "Real", "Real seals float32, and float64 seals as float64"},
		{basic("float32", KindFloat), "Double", "Double seals float64, and float32 seals as float32"},
	} {
		_, err := lowerDeclaration(field(c.goType, c.eqlType), eql)
		fe, ok := err.(*FieldError)
		if !ok || fe.Field != "V" || fe.Reason != c.want {
			t.Errorf("%s into %s: lowerDeclaration = %v, want %q", c.goType, c.eqlType, err, c.want)
		}
	}
	for _, c := range []struct {
		basic, eqlType string
		kind           Kind
		wire           record.Kind
	}{
		{"int32", "Integer", KindInt, record.Int32}, {"int16", "Integer", KindInt, record.Int32}, {"int8", "Integer", KindInt, record.Int32},
		{"uint16", "Integer", KindUint, record.Int32}, {"uint8", "Integer", KindUint, record.Int32},
		{"int", "Integer", KindInt, record.Int32}, {"int64", "Integer", KindInt, record.Int32}, {"uint32", "Integer", KindUint, record.Int32},
		{"int64", "Bigint", KindInt, record.Int64}, {"int", "Bigint", KindInt, record.Int64}, {"int32", "Bigint", KindInt, record.Int64},
		{"int8", "Bigint", KindInt, record.Int64}, {"uint32", "Bigint", KindUint, record.Int64}, {"uint64", "Bigint", KindUint, record.Int64},
		{"float32", "Real", KindFloat, record.Float32}, {"float64", "Double", KindFloat, record.Float64},
	} {
		plan, err := lowerDeclaration(field(basic(c.basic, c.kind), c.eqlType), eql)
		if err != nil {
			t.Errorf("%s into %s: %v", c.basic, c.eqlType, err)
			continue
		}
		if got := plan.Fields[0].Kind; got != c.wire {
			t.Errorf("%s into %s: the plan seals %s, want %s", c.basic, c.eqlType, got, c.wire)
		}
	}
}
