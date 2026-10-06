// Package record is the data form of a declaration as the engine reads it:
// the plan object the guest's se_encrypt_record, se_decrypt_record and
// se_plan_check parse, and the per-field outputs they return. It is shared by
// the encrypt package, which runs plans, by encrypt/gensupport, which lowers
// a generated declaration into one, and by stashgen, which asks the engine
// to check one.
//
// The spellings here are wire format, fixed by stack-encrypt's
// dynamic::record: the output keys "c", "eq", "match", "ore", "ope" and
// "passthrough", and the type names "bool", "int32", "int64", "uint32",
// "uint64", "float32", "float64", "string" and "bytes". A field's context is
// its label — the plan's context segments and the field's identity — nested
// to the left under each part the caller extends it by.
//
// Passthrough fields do not appear in a Plan. The Go SDK keeps them on the
// host: the FFI codec cannot carry every Go type a program stores beside a
// ciphertext (a time.Time, a driver.Valuer), and nothing the engine does to
// a passthrough value could be observed. The one exception is a context
// field: a string field whose value is the context every other field is
// sealed under (the engine's context_field). It crosses the binding as a
// passthrough of type string, because the engine reads it to seal and to
// open, and the stored record carries it in the clear.
package record

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Kind is a plan field's declared type: the data form of the Rust chain's
// `::<F>`. It decides which terms the field derives, not how it seals:
// a field lowered from data seals in vitaminc's self-describing tagged leaf
// encoding whatever its kind. A Rust record derives the same terms, and
// opens the leaf only when its field is a Value; a Rust record over a bare
// u32 or String writes a different leaf, which neither side can open.
type Kind string

// The kinds. The names are vitaminc's ValueKind names, frozen.
const (
	Untyped Kind = ""
	Bool    Kind = "bool"
	Int32   Kind = "int32"
	Int64   Kind = "int64"
	Uint32  Kind = "uint32"
	Uint64  Kind = "uint64"
	Float32 Kind = "float32"
	Float64 Kind = "float64"
	String  Kind = "string"
	Bytes   Kind = "bytes"
)

// Output is one output of a sealed field, by its wire key.
type Output string

// The outputs. Passthrough is not one a Plan's Fields ask for (see the
// package doc); it is the context field's, which Wire writes itself.
const (
	Ciphertext  Output = "c"
	Equality    Output = "eq"
	Match       Output = "match"
	Ore         Output = "ore"
	Ope         Output = "ope"
	Passthrough Output = "passthrough"
)

// EQLKey is the stored key a target field's EQL value rides under: not an
// output a plan asks for (the field names a Target instead), but the key of
// its one node in a sealed record, fixed by stack-encrypt's
// dynamic::record::EQL_KEY.
const EQLKey = "eql"

// IsTerm reports whether the output is an index term.
func (o Output) IsTerm() bool { return o != Ciphertext && o != "" }

// Field is one sealed field of a plan.
type Field struct {
	// Name is the field's name in the declaration: the key of its value in a
	// source and of its outputs in a result.
	Name string
	// Identity is the last segment of the field's label, under the plan's
	// context. It is the name unless a policy pinned another.
	Identity string
	// Kind is the declared type, or Untyped.
	Kind Kind
	// Outputs are the field's outputs: Ciphertext and/or terms, at least one
	// — unless the field names a Target, which has none of its own.
	Outputs []Output
	// Target is the EQL type the field seals into (encrypt_into), such as
	// TextEq, or "". A field has outputs or a target, never both: the EQL
	// type's own plan decides what is sealed and which terms sit beside it,
	// and the engine returns the finished value under EQLKey.
	Target string
}

// IsTarget reports whether the field names an EQL type.
func (f Field) IsTarget() bool { return f.Target != "" }

// HasCiphertext reports whether the field's stored node is opened on
// decrypt: a ciphertext output, or an EQL value.
func (f Field) HasCiphertext() bool {
	if f.IsTarget() {
		return true
	}
	for _, o := range f.Outputs {
		if o == Ciphertext {
			return true
		}
	}
	return false
}

// Plan is a declaration as the engine reads it: one context, any extension,
// and the sealed fields.
type Plan struct {
	// Context is the label every field's label extends: at least one plain
	// segment. The guest requires a field's label to have two or more
	// segments, which the identity supplies. Empty when ContextField is set.
	Context []string
	// ContextField is the name of the record's field whose value is the
	// context, when the declaration takes its context from a field rather
	// than from Context: the engine's context_field. The field is a string,
	// crosses the binding as a passthrough, and is not in Fields. Each
	// field's label is then its identity alone, under that value.
	ContextField string
	// Extension is the caller's parts, nested to the left of every field's
	// label, in order: a tenant, a region.
	Extension []any
	// Fields are the sealed fields, in declared order.
	Fields []Field
}

// ParseContext splits a `context=` value on '/' and checks each segment is
// plain: what a label is, so the ZeroKMS descriptor renders it verbatim.
func ParseContext(s string) ([]string, error) {
	if s == "" {
		return nil, errors.New("the context is empty")
	}
	segments := strings.Split(s, "/")
	for i, seg := range segments {
		if err := CheckSegment(seg); err != nil {
			return nil, fmt.Errorf("context %q: segment %d %v", s, i, err)
		}
	}
	return segments, nil
}

// CheckSegment is the one rule for a plain label segment, the same as
// stack-encrypt's Label::check_segment: non-empty, no control or invisible
// format character, none of '/', '(' and ')', and not beginning like another
// descriptor form ("b64:", a digit or '-'). The shared fixture
// packages/stack-encrypt/tests/fixtures/label_segments.json holds the two
// implementations together.
func CheckSegment(s string) error {
	if s == "" {
		return errors.New("is empty")
	}
	if strings.HasPrefix(s, "b64:") || s[0] == '-' || (s[0] >= '0' && s[0] <= '9') {
		return errors.New("begins like another descriptor form (b64:, a digit or -)")
	}
	for _, r := range s {
		if r == '/' {
			return errors.New("contains '/', the separator")
		}
		if unicode.IsControl(r) || r == '(' || r == ')' {
			return fmt.Errorf("contains %q, which the descriptor reserves", r)
		}
		if strings.ContainsRune(invisible, r) {
			return fmt.Errorf("contains %q, an invisible format character", r)
		}
	}
	return nil
}

// invisible is the format characters with no glyph of their own: the soft
// hyphen, the Arabic letter mark, the Mongolian vowel separator, the
// zero-width characters, the bidirectional embeddings, overrides and
// isolates, and the byte-order mark. unicode.IsControl covers only Cc;
// these are Cf. A name containing one prints like another name in the
// ZeroKMS log, so they are refused beside the control characters. The same
// list as Rust's Label::INVISIBLE.
const invisible = "\u00ad\u061c\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff"

// CheckPart refuses a context extension part that is not a string, a byte
// slice or an integer the codec carries.
func CheckPart(part any) error {
	switch part.(type) {
	case string, []byte, int32, int64, uint32, uint64, int:
		return nil
	default:
		return fmt.Errorf("%T is not a context part (string, []byte or integer)", part)
	}
}

// Validate checks what the host can check before the engine sees the plan:
// a context, plain segments, at least one field, names and identities once,
// outputs once and at least one, known kinds, and extension parts the codec
// carries. The engine's own rules — which index a kind admits, what the
// builder refuses — are the engine's, asked through se_plan_check.
func (p *Plan) Validate() error {
	switch {
	case p.ContextField != "" && len(p.Context) > 0:
		return errors.New("record: the plan has a context and a context field; it takes one")
	case p.ContextField != "":
		// The field's name is its label segment on the wire, so it has to
		// be a plain one.
		if err := CheckSegment(p.ContextField); err != nil {
			return fmt.Errorf("record: context field %q %v", p.ContextField, err)
		}
	case len(p.Context) == 0:
		return errors.New("record: the plan has no context")
	}
	for i, seg := range p.Context {
		if err := CheckSegment(seg); err != nil {
			return fmt.Errorf("record: context segment %d %v", i, err)
		}
	}
	for _, part := range p.Extension {
		if err := CheckPart(part); err != nil {
			return fmt.Errorf("record: context extension: %v", err)
		}
	}
	if len(p.Fields) == 0 {
		return errors.New("record: the plan has no sealed field")
	}
	names, identities := map[string]bool{}, map[string]bool{}
	if p.ContextField != "" {
		names[p.ContextField], identities[p.ContextField] = true, true
	}
	for _, f := range p.Fields {
		if f.Name == "" {
			return errors.New("record: a field has no name")
		}
		if names[f.Name] {
			return fmt.Errorf("record: field %q is declared twice", f.Name)
		}
		names[f.Name] = true
		identity := f.identity()
		if err := CheckSegment(identity); err != nil {
			return fmt.Errorf("record: field %q: identity %q %v", f.Name, identity, err)
		}
		if identities[identity] {
			return fmt.Errorf("record: field %q: identity %q is used twice", f.Name, identity)
		}
		identities[identity] = true
		if !f.Kind.Known() {
			return fmt.Errorf("record: field %q: unknown kind %q", f.Name, f.Kind)
		}
		if f.IsTarget() {
			if len(f.Outputs) != 0 {
				return fmt.Errorf("record: field %q names the EQL type %s and outputs; a field has one or the other", f.Name, f.Target)
			}
			continue
		}
		if len(f.Outputs) == 0 {
			return fmt.Errorf("record: field %q has no output", f.Name)
		}
		seen := map[Output]bool{}
		for _, o := range f.Outputs {
			switch o {
			case Ciphertext, Equality, Match, Ore, Ope:
			default:
				return fmt.Errorf("record: field %q: unknown output %q", f.Name, o)
			}
			if seen[o] {
				return fmt.Errorf("record: field %q: output %q is asked for twice", f.Name, o)
			}
			seen[o] = true
		}
	}
	return nil
}

// Known reports whether k is a kind that the engine names; Untyped is one.
func (k Kind) Known() bool {
	switch k {
	case Untyped, Bool, Int32, Int64, Uint32, Uint64, Float32, Float64, String, Bytes:
		return true
	}
	return false
}

func (f Field) identity() string {
	if f.Identity != "" {
		return f.Identity
	}
	return f.Name
}

// Field returns the field named, or nil.
func (p *Plan) Field(name string) *Field {
	for i := range p.Fields {
		if p.Fields[i].Name == name {
			return &p.Fields[i]
		}
	}
	return nil
}

// Wire renders the plan as the guest parses it: per field, its context
// (the label, extended), its outputs or its target, and its type; with a
// context field, the plan-level "context_field" key and that field's own
// entry, a passthrough of type string. Validate first.
func (p *Plan) Wire() vcvalue.Object {
	out := make(vcvalue.Object, 0, len(p.Fields)+2)
	if p.ContextField != "" {
		out = append(out,
			vcvalue.Field{Key: "context_field", Value: p.ContextField},
			vcvalue.Field{Key: p.ContextField, Value: vcvalue.Object{
				{Key: "context", Value: p.FieldContext(Field{Name: p.ContextField})},
				{Key: "outputs", Value: []any{string(Passthrough)}},
				{Key: "type", Value: string(String)},
			}},
		)
	}
	for _, f := range p.Fields {
		spec := vcvalue.Object{{Key: "context", Value: p.FieldContext(f)}}
		if f.IsTarget() {
			spec = append(spec, vcvalue.Field{Key: "target", Value: f.Target})
		} else {
			outputs := make([]any, len(f.Outputs))
			for i, o := range f.Outputs {
				outputs[i] = string(o)
			}
			spec = append(spec, vcvalue.Field{Key: "outputs", Value: outputs})
		}
		if f.Kind != Untyped {
			spec = append(spec, vcvalue.Field{Key: "type", Value: string(f.Kind)})
		}
		out = append(out, vcvalue.Field{Key: f.Name, Value: spec})
	}
	return out
}

// FieldContext is one field's context as the guest reads it: the label as a
// flat list of its segments, then each extension part nested to the left —
// [[["users", "age"], 7], "eu"] — exactly the shape se_term takes for a
// probe of that field. Under a context field the label is the identity
// alone: [["age"], 7].
func (p *Plan) FieldContext(f Field) any {
	label := make([]any, 0, len(p.Context)+1)
	for _, s := range p.Context {
		label = append(label, s)
	}
	label = append(label, f.identity())
	var node any = label
	for _, part := range p.Extension {
		node = []any{node, ownPart(part)}
	}
	return node
}

// ownPart copies a byte-slice part so a caller's buffer reused later does
// not change a context already built.
func ownPart(part any) any {
	if b, ok := part.([]byte); ok {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	return part
}

// Descriptor renders a field's label as ZeroKMS logs it, for messages.
// Under a context field the context is the record's, so the descriptor
// names the field in its place: "<tenant>/age".
func (p *Plan) Descriptor(f Field) string {
	if p.ContextField != "" {
		return "<" + p.ContextField + ">/" + f.identity()
	}
	return strings.Join(append(append([]string{}, p.Context...), f.identity()), "/")
}

// Source is one record's plaintext for the engine: each sealed field's value
// by name, and the context field's string when the plan has one.
// Passthrough and omitted fields are not in it.
type Source = map[string]any

// Outputs is what the engine produced for one sealed field, or what it
// stored for the context field.
type Outputs struct {
	// Ciphertext is the frozen leaf bytes, or nil for an index-only field
	// or a target field.
	Ciphertext []byte
	// Terms are the index terms by output, each its frozen bytes.
	Terms map[Output][]byte
	// EQL is the EQL value's JSON bytes for a field that names a Target.
	EQL []byte
	// Context is the context field's value as the record stores it, in the
	// clear, and nothing for any other field.
	Context string
}

// Sealed is one record as stored: each sealed field's outputs by name, and
// the context field's under its name when the plan has one.
type Sealed = map[string]Outputs

// Target is one EQL type as se_targets lists it. The entry's keys are wire
// format, written by eql-bindings' serialiser and read by [ParseTargets]:
// name, family, suffix, plaintext (a ValueKind name, or null), sql_domain,
// indexes (eq | match | ore | ope | json), query (or null), query_sql_domain
// (or null), producible and reason (or null).
type Target struct {
	// Name is the Go type name, and the value of encrypt_into: TextEq.
	Name string
	// Family and Suffix are the two halves of the name: Text, Eq.
	Family string
	Suffix string
	// Plaintext is the kind the type seals, or Untyped when the entry says
	// null.
	Plaintext Kind
	// SQLDomain is the Postgres domain of the stored value.
	SQLDomain string
	// Indexes are the terms the type carries.
	Indexes []Output
	// Query is the Go type name of the query value, or "" for none.
	Query string
	// QuerySQLDomain is the Postgres domain of the query value, or "".
	QuerySQLDomain string
	// Producible says whether this build of the engine produces the type;
	// Reason says why not when it does not.
	Producible bool
	Reason     string
}
