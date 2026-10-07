package stashgen

import (
	"context"
	"fmt"
	"strings"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Engine answers the generator's questions about what the Rust engine can do.
// The generator holds no copy of the engine's rules: every refusal about an
// index, an EQL type or a field type comes from here.
//
// [GuestEngine] is the SDK's implementation: the WASI guest that package
// encrypt embeds, asked through se_plan_check and se_targets.
type Engine interface {
	// EQLTypes lists the EQL types the engine can produce: each name, its
	// plaintext kind, its indexes and its query type.
	EQLTypes(ctx context.Context) ([]EQLType, error)
	// Check refuses a declaration the engine cannot run: an index or an EQL
	// type that does not apply to a field's Go type, a field type it cannot
	// seal, an EQL type it cannot produce, or an index option it cannot
	// carry. The error names the field.
	Check(ctx context.Context, d Declaration) error
}

// EQLType is one EQL type the engine produces, such as TextEq.
type EQLType struct {
	// Name is the Go type name in encrypt/eql, and the value of encrypt_into.
	Name string
	// Plaintext is the kind of Go value the type seals.
	Plaintext Kind
	// Indexes are the terms the type carries.
	Indexes []IndexName
	// Query is the Go type name of the type's query value, such as
	// TextEqQuery, or "" for a type with no terms.
	Query string
	// Producible says whether this build of the engine produces the type;
	// Reason says why not when it does not.
	Producible bool
	Reason     string
}

// GuestEngine is the engine the SDK embeds: the WASI guest in package
// encrypt, asked through its se_plan_check and se_targets exports. It holds
// no credentials and makes no request. Close it when done.
func GuestEngine(ctx context.Context) (Engine, error) {
	checker, err := encrypt.NewChecker(ctx)
	if err != nil {
		return nil, err
	}
	return &guestEngine{checker: checker}, nil
}

type guestEngine struct {
	checker *encrypt.Checker
}

// Close releases the guest. The Engine interface does not name it, so a
// caller that holds the engine as an Engine asserts to io.Closer.
func (e *guestEngine) Close() error { return e.checker.Close() }

// EQLTypes asks the guest which EQL types it produces.
func (e *guestEngine) EQLTypes(ctx context.Context) ([]EQLType, error) {
	targets, err := e.checker.Targets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]EQLType, 0, len(targets))
	for _, t := range targets {
		eqlType := EQLType{Name: t.Name, Plaintext: kindOfWire(t.Plaintext), Query: t.Query, Producible: t.Producible, Reason: t.Reason}
		for _, term := range t.Indexes {
			if name, ok := indexOfOutput[term]; ok {
				eqlType.Indexes = append(eqlType.Indexes, name)
			}
		}
		out = append(out, eqlType)
	}
	return out, nil
}

// Check asks the guest about the declaration one field at a time, so the
// error names the field, then about the whole: the engine's rules across
// fields (two fields under one identity) show only there.
func (e *guestEngine) Check(ctx context.Context, d Declaration) error {
	eqlTypes, err := e.EQLTypes(ctx)
	if err != nil {
		return err
	}
	plan, err := lowerDeclaration(d, eqlTypes)
	if err != nil {
		return err
	}
	if len(plan.Fields) == 0 {
		// Nothing crosses the binding: an all-passthrough struct, which the
		// generator refuses before it gets here.
		return nil
	}
	for _, f := range plan.Fields {
		one := &record.Plan{Context: plan.Context, Fields: []record.Field{f}}
		if err := e.checker.Check(ctx, one); err != nil {
			field := d.field(f.Name)
			return &FieldError{Type: d.Type, Field: field.GoName, Reason: fmt.Sprintf(
				"the engine refuses the declaration: %s over a %s value under %q (%v)",
				describeOutputs(f.Outputs), kindWord(f.Kind), plan.Descriptor(f), err)}
		}
	}
	if err := e.checker.Check(ctx, plan); err != nil {
		return &FieldError{Type: d.Type, Reason: fmt.Sprintf("the engine refuses the declaration as a whole: %v", err)}
	}
	return nil
}

// lowerDeclaration is the generator's lowering of a declaration to the plan
// the engine reads: the same shape gensupport lowers the generated
// declaration to. Passthrough and omitted fields stay on the host.
func lowerDeclaration(d Declaration, eqlTypes []EQLType) (*record.Plan, error) {
	segments, err := record.ParseContext(d.Context)
	if err != nil {
		return nil, &FieldError{Type: d.Type, Reason: err.Error()}
	}
	plan := &record.Plan{Context: segments}
	if d.Opaque {
		// gensupport seals an opaque struct as one JSON document under
		// <context>/value; see gensupport.OpaqueField.
		plan.Fields = []record.Field{{Name: "value", Kind: record.Bytes, Outputs: []record.Output{record.Ciphertext}}}
		return plan, nil
	}
	for _, f := range d.Fields {
		if !f.Sealed() {
			continue
		}
		rf := record.Field{Name: f.Name, Identity: f.Identity, Kind: wireKind(f.GoType)}
		switch f.Verb {
		case VerbEncryptInto:
			// The reader refused anything the engine does not produce; a
			// producible type reaches the engine's check in the next build,
			// which lowers it. Until then no type is producible.
			return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine cannot seal into the EQL type %s in this build", f.EQLType)}
		case VerbEncrypt, VerbEncryptIndex:
			rf.Outputs = append(rf.Outputs, record.Ciphertext)
		}
		for _, idx := range f.Indexes {
			if len(idx.Options) > 0 {
				// The record plan carries match options, but the guest's
				// query export derives a term under the default options
				// only, so a stored term with others would match no query.
				// The rule belongs in the guest (se_plan_check) once se_term
				// takes options.
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("index %s: a query term uses only the default index options, so this build refuses options", idx)}
			}
			out, ok := outputOfIndex[idx.Name]
			if !ok {
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine does not derive the %s index yet", idx.Name)}
			}
			rf.Outputs = append(rf.Outputs, out)
		}
		plan.Fields = append(plan.Fields, rf)
	}
	return plan, nil
}

var outputOfIndex = map[IndexName]record.Output{
	IndexEquality: record.Equality, IndexMatch: record.Match, IndexOre: record.Ore, IndexOpe: record.Ope,
}

var indexOfOutput = map[record.Output]IndexName{
	record.Equality: IndexEquality, record.Match: IndexMatch, record.Ore: IndexOre, record.Ope: IndexOpe,
}

// wireKind is the record kind of a Go type: the same mapping the emitter
// writes into the generated declaration (kindExpr).
func wireKind(t GoType) record.Kind {
	switch kindExpr(t) {
	case "gensupport.String":
		return record.String
	case "gensupport.Bool":
		return record.Bool
	case "gensupport.Bytes":
		return record.Bytes
	case "gensupport.Int32":
		return record.Int32
	case "gensupport.Int64":
		return record.Int64
	case "gensupport.Uint32":
		return record.Uint32
	case "gensupport.Uint64":
		return record.Uint64
	case "gensupport.Float32":
		return record.Float32
	case "gensupport.Float64":
		return record.Float64
	}
	return record.Untyped
}

// kindOfWire is the generator's kind for a wire kind, for an EQL type's
// plaintext.
func kindOfWire(k record.Kind) Kind {
	switch k {
	case record.String:
		return KindString
	case record.Bool:
		return KindBool
	case record.Bytes:
		return KindBytes
	case record.Int32, record.Int64:
		return KindInt
	case record.Uint32, record.Uint64:
		return KindUint
	case record.Float32, record.Float64:
		return KindFloat
	}
	return KindOther
}

func kindWord(k record.Kind) string {
	if k == record.Untyped {
		return "composite"
	}
	return string(k)
}

func describeOutputs(outputs []record.Output) string {
	words := make([]string, 0, len(outputs))
	for _, o := range outputs {
		if o == record.Ciphertext {
			words = append(words, "a ciphertext")
			continue
		}
		words = append(words, string(indexOfOutput[o])+" index")
	}
	return strings.Join(words, ", ")
}

// field finds a declared field by its declaration name.
func (d Declaration) field(name string) Field {
	for _, f := range d.Fields {
		if f.Name == name {
			return f
		}
	}
	return Field{}
}
