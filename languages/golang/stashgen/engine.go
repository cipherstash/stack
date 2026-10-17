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
// index, an EQL type or a field type comes from here, and so does every
// operator a field's query methods name.
//
// [GuestEngine] is the SDK's implementation: the WASI guest that package
// encrypt embeds, asked through se_plan_check, se_targets and
// se_operators.
type Engine interface {
	// EQLTypes lists the EQL types the engine can produce: each name, its
	// plaintext kind, its indexes and its query type.
	EQLTypes(ctx context.Context) ([]EQLType, error)
	// Check refuses a declaration the engine cannot run: an index or an EQL
	// type that does not apply to a field's Go type, a field type it cannot
	// seal, an EQL type it cannot produce, or an index option it cannot
	// carry. The error names the field. For a declaration it accepts, it
	// lists the operators the engine answers on each sealed field, by the
	// field's declared name, in the engine's order: the generator writes one
	// query method for each.
	Check(ctx context.Context, d Declaration) (map[string][]Operator, error)
}

// Operator is one operator the engine answers on a field, such as eq or
// matches: the generated method's name, its input and its result follow
// from it.
type Operator struct {
	// Name is the operator's name, as a query names it: eq, lt, lte, gt,
	// gte, between or matches.
	Name string
	// Probabilistic says the server's answer can hold false positives, so
	// the query's type carries Verify and TargetLimit; an exact answer's
	// carries neither.
	Probabilistic bool
	// Pair says the operator takes two values, low then high, as between
	// does.
	Pair bool
	// Index is the index that answers it: the field's own, or its EQL
	// type's.
	Index IndexName
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

	// wire is the engine's exact plaintext kind (int32, not just an
	// integer), when the engine named it. Plaintext is the coarse kind a
	// field's Go type is compared with first; wire then holds the width.
	wire record.Kind
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
	// eqlTypes is the guest's answer to se_targets, asked once: it is fixed
	// for the guest's build.
	eqlTypes []EQLType
}

// Close releases the guest. The Engine interface does not name it, so a
// caller that holds the engine as an Engine asserts to io.Closer.
func (e *guestEngine) Close() error { return e.checker.Close() }

// EQLTypes asks the guest which EQL types it produces, once.
func (e *guestEngine) EQLTypes(ctx context.Context) ([]EQLType, error) {
	if e.eqlTypes != nil {
		return e.eqlTypes, nil
	}
	targets, err := e.checker.Targets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]EQLType, 0, len(targets))
	for _, t := range targets {
		eqlType := EQLType{Name: t.Name, Plaintext: kindOfWire(t.Plaintext), Query: t.Query, Producible: t.Producible, Reason: t.Reason, wire: t.Plaintext}
		for _, term := range t.Indexes {
			if name, ok := indexOfOutput[term]; ok {
				eqlType.Indexes = append(eqlType.Indexes, name)
			}
		}
		out = append(out, eqlType)
	}
	e.eqlTypes = out
	return out, nil
}

// Check lowers the declaration once and asks the guest about it one field
// at a time, so the error names the field, then about the whole: the
// engine's rules across fields (two fields under one identity) show only
// there. Then it asks, field by field, which operators the engine answers
// (se_operators), on the same plan.
func (e *guestEngine) Check(ctx context.Context, d Declaration) (map[string][]Operator, error) {
	eqlTypes, err := e.EQLTypes(ctx)
	if err != nil {
		return nil, err
	}
	plan, err := lowerDeclaration(d, eqlTypes)
	if err != nil {
		return nil, err
	}
	if len(plan.Fields) == 0 {
		// Nothing crosses the binding: an all-passthrough struct, which the
		// generator refuses before it gets here.
		return map[string][]Operator{}, nil
	}
	for _, f := range plan.Fields {
		one := &record.Plan{Context: plan.Context, ContextField: plan.ContextField, Fields: []record.Field{f}}
		if err := e.checker.Check(ctx, one); err != nil {
			field := d.field(f.Name)
			return nil, &FieldError{Type: d.Type, Field: field.GoName, Reason: fmt.Sprintf(
				"the engine refuses the declaration: %s over a %s value under %q (%v)",
				describeField(f), kindWord(f.Kind), plan.Descriptor(f), err)}
		}
	}
	if err := e.checker.Check(ctx, plan); err != nil {
		return nil, &FieldError{Type: d.Type, Reason: fmt.Sprintf("the engine refuses the declaration as a whole: %v", err)}
	}
	out := make(map[string][]Operator, len(plan.Fields))
	if d.Opaque {
		// An opaque struct is one ciphertext with no index: no query.
		return out, nil
	}
	for _, f := range plan.Fields {
		answered, err := e.checker.Operators(ctx, plan, f.Name)
		if err != nil {
			return nil, &FieldError{Type: d.Type, Field: d.field(f.Name).GoName, Reason: fmt.Sprintf("the engine's operators: %v", err)}
		}
		ops := make([]Operator, 0, len(answered))
		for _, o := range answered {
			index, ok := indexOfOutput[o.Index]
			if !ok {
				return nil, &FieldError{Type: d.Type, Field: d.field(f.Name).GoName, Reason: fmt.Sprintf("the engine answers %s through the index %q, which the generator does not know", o.Name, o.Index)}
			}
			ops = append(ops, Operator{Name: o.Name, Probabilistic: o.Fidelity == record.Probabilistic, Pair: o.Pair, Index: index})
		}
		out[f.Name] = ops
	}
	return out, nil
}

// lowerDeclaration is the generator's lowering of a declaration to the plan
// the engine reads: the same shape gensupport lowers the generated
// declaration to. Passthrough and omitted fields stay on the host.
func lowerDeclaration(d Declaration, eqlTypes []EQLType) (*record.Plan, error) {
	plan := &record.Plan{ContextField: d.ContextField}
	if d.ContextField == "" {
		segments, err := record.ParseContext(d.Context)
		if err != nil {
			return nil, &FieldError{Type: d.Type, Reason: err.Error()}
		}
		plan.Context = segments
	}
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
			if len(eqlTypes) == 0 {
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: "EQL types are not available yet; the engine produces none in this build"}
			}
			var eqlType *EQLType
			for i := range eqlTypes {
				if eqlTypes[i].Name == f.EQLType {
					eqlType = &eqlTypes[i]
				}
			}
			if eqlType == nil {
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine cannot produce the EQL type %s yet: no EQL type has that name", f.EQLType)}
			}
			if !eqlType.Producible {
				// The engine's own reason, from se_targets: the generator
				// holds no copy of why a type waits.
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine cannot produce the EQL type %s yet: %s", f.EQLType, eqlType.Reason)}
			}
			// An integer EQL type takes any Go integer type whose every
			// value fits its kind (ADR-0002): the field is sealed at the
			// type's kind, and gensupport converts the value.
			if wire, fits := intoKind(f.GoType, eqlType.wire); fits {
				rf.Kind = wire
			} else if _, _, integer := integerRange(eqlType.wire); integer && (f.GoType.Kind == KindInt || f.GoType.Kind == KindUint || f.GoType.Kind == KindInt128 || f.GoType.Kind == KindUint128) {
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals %s, and not every %s fits it", f.EQLType, eqlType.wire, f.GoType)}
			} else {
				// The engine checks the kind too (se_plan_check refuses a
				// "type" other than the EQL type's plaintext); saying it
				// here names the two kinds.
				if eqlType.Plaintext != KindOther && eqlType.Plaintext != f.GoType.Kind {
					return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals a %s, and %s is %s", f.EQLType, eqlType.Plaintext, f.GoType, f.GoType.Kind)}
				}
				// The width too: Real seals a float32 and Double a float64.
				if eqlType.wire != record.Untyped && rf.Kind != eqlType.wire {
					return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals %s, and %s seals as %s", f.EQLType, eqlType.wire, f.GoType, rf.Kind)}
				}
			}
			// An EQL value is stored under a table and a column: the struct's
			// context is the table and the field's name the column, so a
			// context of two or more segments leaves the field no column,
			// and a struct whose context is one of its fields has no table
			// of its own. The engine refuses both too (se_plan_check);
			// naming them here names the field.
			if d.ContextField != "" {
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s is stored under a table and a column, and a struct whose context is its field %q has no table of its own; give the struct a context= tag", f.EQLType, d.ContextField)}
			}
			if len(plan.Context) != 1 {
				return nil, &FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s is stored under a table and a column, and the context %q has %d segments, not one", f.EQLType, d.Context, len(plan.Context))}
			}
			rf.Target = f.EQLType
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
// writes into the generated declaration (kindExpr). Each integer type has the
// kind of its own width.
func wireKind(t GoType) record.Kind {
	switch t.Kind {
	case KindString:
		return record.String
	case KindBool:
		return record.Bool
	case KindBytes:
		return record.Bytes
	case KindInt:
		switch t.Basic {
		case "int8":
			return record.Int8
		case "int16":
			return record.Int16
		case "int32", "rune":
			return record.Int32
		}
		return record.Int64
	case KindUint:
		switch t.Basic {
		case "uint8", "byte":
			return record.Uint8
		case "uint16":
			return record.Uint16
		case "uint32":
			return record.Uint32
		}
		return record.Uint64
	case KindFloat:
		if t.Basic == "float32" {
			return record.Float32
		}
		return record.Float64
	case KindInt128:
		return record.Int128
	case KindUint128:
		return record.Uint128
	case KindDate:
		return record.Date
	case KindTimestamp:
		return record.Timestamp
	case KindDecimal:
		return record.Decimal
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
	case record.Int8, record.Int16, record.Int32, record.Int64:
		return KindInt
	case record.Uint8, record.Uint16, record.Uint32, record.Uint64:
		return KindUint
	case record.Int128:
		return KindInt128
	case record.Uint128:
		return KindUint128
	case record.Float32, record.Float64:
		return KindFloat
	case record.Date:
		return KindDate
	case record.Timestamp:
		return KindTimestamp
	case record.Decimal:
		return KindDecimal
	}
	return KindOther
}

// integerRange is an integer wire kind's signedness and width in bits, or
// false for any other kind.
func integerRange(k record.Kind) (signed bool, bits int, ok bool) {
	switch k {
	case record.Int8:
		return true, 8, true
	case record.Int16:
		return true, 16, true
	case record.Int32:
		return true, 32, true
	case record.Int64:
		return true, 64, true
	case record.Int128:
		return true, 128, true
	case record.Uint8:
		return false, 8, true
	case record.Uint16:
		return false, 16, true
	case record.Uint32:
		return false, 32, true
	case record.Uint64:
		return false, 64, true
	case record.Uint128:
		return false, 128, true
	}
	return false, 0, false
}

// intoKind is the kind a field of Go type t is sealed as when it is stored
// as an EQL type whose plaintext is the integer kind target: target itself
// when every value of t fits it (ADR-0002: an int8 into a smallint, an int32
// into a bigint, a uint16 into an integer), so the generated declaration names
// target and gensupport converts the value; false when t is not an integer or
// some of its values do not fit.
func intoKind(t GoType, target record.Kind) (record.Kind, bool) {
	fromSigned, fromBits, fromInt := integerRange(wireKind(t))
	toSigned, toBits, toInt := integerRange(target)
	if !fromInt || !toInt {
		return record.Untyped, false
	}
	fits := (fromSigned == toSigned && toBits >= fromBits) || (!fromSigned && toSigned && toBits > fromBits)
	return target, fits
}

func kindWord(k record.Kind) string {
	if k == record.Untyped {
		return "composite"
	}
	return string(k)
}

// describeField names what the engine was asked for a field: the EQL type
// it names, or its outputs. For an EQL type the engine refuses, the refusal
// is the engine's (an unknown or unproducible type, a kind other than its
// plaintext, an extended context); the name is what a reader needs.
func describeField(f record.Field) string {
	if f.IsTarget() {
		return "the EQL type " + f.Target
	}
	return describeOutputs(f.Outputs)
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
