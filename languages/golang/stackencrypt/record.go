package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Record plans: per field, which context to bind and which outputs to
// derive. A plan is a value ([Plan]) with two sources: `stash` struct tags
// ([PlanFromTags], the default, and the Go stand-in for the Rust derive), or
// an explicit plan built with [NewPlan] and passed through [WithPlan] — for
// structs whose source cannot carry a tag, such as generated code.
//
// A struct field's `stash` tag says what to do with it:
//
//	type User struct {
//	    ID    int64  `stash:"-"`                                  // not sent to the guest
//	    Age   uint32 `stash:"context=users/age,index=eq;ore"`     // sealed + equality and ORE terms
//	    Email string `stash:"context=users/email,index=eq;match"` // sealed + equality and match terms
//	    Notes string `stash:"context=users/notes"`                // sealed only
//	}
//
// Options are comma-separated: `context=<table>/<column>` (required for a
// planned field — the field's own context; see [FieldPlan.Context]),
// `index=<kind>[;<kind>]`
// (eq, match, ore, ope), and `name=<wire name>` (the record key; the Go
// field name otherwise). A field tagged `-` or `plain`, or not tagged at
// all, is not part of the record: it never crosses the boundary, and stays
// the caller's to store. Unexported fields are ignored.
//
// The same plan, built by hand:
//
//	plan, err := stackencrypt.NewPlan(
//	    stackencrypt.FieldPlan{
//	        Field:   "Age",
//	        Context: "users/age",
//	        Terms: []stackencrypt.TermKind{
//	            stackencrypt.Equality, stackencrypt.Ore,
//	        },
//	    },
//	    stackencrypt.FieldPlan{
//	        Field:   "Email",
//	        Context: "users/email",
//	        Terms: []stackencrypt.TermKind{
//	            stackencrypt.Equality, stackencrypt.Match,
//	        },
//	    },
//	    stackencrypt.FieldPlan{Field: "Notes", Context: "users/notes"},
//	)
//	records, err := cipher.EncryptRecords(
//	    ctx, users, stackencrypt.WithPlan(plan),
//	)
//
// Every planned field is sealed (the `"c"` output). What the guest receives
// is the same object whichever way the plan was built. The context each
// field binds is the plan's part, extended by [ExtendContext] parts exactly
// as the Rust derive extends a field's context by the caller's:
// NewContext(part).With(p1).With(p2).

// EncryptedField is one field's outputs from EncryptRecords: the sealed
// ciphertext and whichever index terms the plan asked for (nil otherwise).
type EncryptedField struct {
	// Ciphertext is the field's sealed value: a Sealed leaf for a scalar,
	// or the same nested shape Cipher.Encrypt returns for a composite.
	Ciphertext any
	Equality   EqualityTerm
	Match      MatchTerm
	Ore        OreTerm
	Ope        OpeTerm
}

// EncryptedRecord is one record's planned fields, by wire name.
type EncryptedRecord map[string]EncryptedField

// RecordOption adjusts one record call: [Cipher.EncryptRecords],
// [Cipher.EncryptRecord], [Cipher.DecryptRecords], [Cipher.DecryptRecord]
// and the Client forms of the last two. An option is a value built by one
// of the functions below, and a call applies the options it is given in
// order.
//
// A RecordOption that is not also an [Option], such as [WithPlan], means
// something only on a record call, so handing it to [Cipher.Term] does not
// compile.
type RecordOption interface {
	applyRecord(*recordOptions)
}

// Option is a [RecordOption] that the probe call, [Cipher.Term], accepts
// as well: what a record and the probe that matches it must agree on.
// Every Option is a RecordOption, so one value serves the encrypt, decrypt
// and probe calls alike, and the three cannot drift apart:
//
//	tenant := stackencrypt.ExtendContext(uint64(tenantID))
//	rows, err := cipher.EncryptRecords(ctx, users, tenant)
//	probe, err := cipher.Term(ctx, "bob@example.com", email, stackencrypt.Equality, tenant)
//	err = cipher.DecryptRecords(ctx, rows, &back, tenant)
type Option interface {
	RecordOption
	applyTerm(*termOptions)
}

type recordOptions struct {
	extension []any
	plan      Plan
}

type termOptions struct {
	extension []any
}

// contextExtension is what [ExtendContext] returns.
type contextExtension struct{ parts []any }

// appendTo adds the extension's parts after any an earlier option gave:
// the one rule for combining extensions, shared by the record calls and
// the probe so the two cannot combine them differently.
func (e contextExtension) appendTo(ext *[]any) {
	*ext = append(*ext, e.parts...)
}

func (e contextExtension) applyRecord(o *recordOptions) { e.appendTo(&o.extension) }

func (e contextExtension) applyTerm(o *termOptions) { e.appendTo(&o.extension) }

// ExtendContext extends every field's context by parts, in order, the way
// the Rust derive extends a field's context by the caller's
// (encrypt_into_with_context): a field tagged context=users/age with
// ExtendContext(uint64(7)) binds [["users", "age"], 7]. On [Cipher.Term] it
// extends the probe's context the same way, so a probe built under the
// extension a record was written under compares against that record's
// terms, and under any other extension, or none, against nothing.
//
// The same extension must be given to decrypt the records. A part's type
// is part of the context (an int crosses as int64, so uint64(7) and 7 are
// different contexts), which is why an extension is best held in one value
// and passed to every call rather than spelled afresh at each. The option
// owns its parts: a byte-slice part is copied, so a caller's buffer reused
// after the call does not change what the option extends by.
//
// Several ExtendContext options on one call join in order:
// ExtendContext(a), ExtendContext(b) is the same context as
// ExtendContext(a, b), on a record call and on Term alike. So each call
// must receive a given extension once. A helper that always adds the
// tenant, called by code that adds the tenant as well, writes records
// under [field, tenant, tenant], and a probe built with the tenant once
// matches none of them, with no error.
//
// A part is checked when a call applies it, not here: a part that is not
// a string, a byte slice or an integer fails the call it is given to.
func ExtendContext(parts ...any) Option {
	owned := make([]any, len(parts))
	for i, part := range parts {
		owned[i] = ownPart(part)
	}
	return contextExtension{parts: owned}
}

// extend is c extended by every part of ext, in order: the one definition
// of how an extension applies, shared by the record plan and the probe so
// the two cannot disagree.
func extend(c Context, ext []any) (Context, error) {
	for _, part := range ext {
		var err error
		if c, err = c.With(part); err != nil {
			return Context{}, err
		}
	}
	return c, nil
}

// planOption is what [WithPlan] returns.
type planOption struct{ plan Plan }

func (p planOption) applyRecord(o *recordOptions) { o.plan = p.plan }

// WithPlan encrypts or decrypts records under an explicit plan instead of
// the struct's `stash` tags.
//
// What decryption needs from the encrypting plan is what names and keys
// the ciphertext: each field's record Name, its Context (extended by the
// same [ExtendContext] parts), and the set of fields that carry a
// ciphertext. Field only selects which Go field the plaintext is written
// to, so it may differ between the two sides: a record encrypted from a
// generated struct may be decrypted into a domain struct under a plan
// with the same Names and Contexts. Terms are one-way outputs, derived on
// encryption and never sent to decrypt, so they need not match either.
func WithPlan(p Plan) RecordOption {
	return planOption{plan: p}
}

// FieldPlan is one planned field of a record.
type FieldPlan struct {
	// Field is the Go struct field name. It must be exported.
	Field string
	// Name is the record key the field's outputs are stored under: the
	// column name, in EQL terms. Field when empty.
	Name string
	// Context is the field's own encryption context; the record call
	// extends it by any ExtendContext parts. Required.
	//
	// "users/age" is a table and a column: it crosses the boundary as the
	// two-part context ["users", "age"] — what a Rust `#[derive(EncryptFrom)]`
	// with `struct = .., context = "users"` binds its `age` field under, and
	// what renders the ZeroKMS descriptor users/age. A probe for the field is
	// built with [PlanContext]. A context with no "/" is one part, as
	// NewContext makes it; more than one "/", or an empty side, is refused.
	Context string
	// Terms lists the terms to derive beside the ciphertext, in order.
	Terms []TermKind
}

// Plan is a record plan: which fields of a struct to seal, under which
// context, with which terms. It is an immutable value; the zero Plan
// means "the struct's tags". Build one with [NewPlan] or [PlanFromTags].
type Plan struct {
	d *planData
}

// planData is the validated, shared body of a Plan. Every copy of the Plan
// points at the same body, so it is never mutated after NewPlan returns.
type planData struct {
	fields []planField
}

// planField is a validated FieldPlan: Name filled in, every term kind
// known and named once.
type planField struct {
	field   string
	name    string
	context string
	terms   []TermKind
}

// outputs spells the field's outputs the way the guest reads them: the
// ciphertext first, then each term.
func (f planField) outputs() []string {
	out := make([]string, 1, 1+len(f.terms))
	out[0] = "c"
	for _, k := range f.terms {
		out = append(out, k.String())
	}
	return out
}

// NewPlan validates the fields and returns the plan. Every field needs a
// Field and a Context; Go field names must be unique, and so must record
// names (Name, or Field); Terms must be kinds this package defines, each
// at most once per field. A plan is built once and reused across calls,
// like the type it describes.
func NewPlan(fields ...FieldPlan) (Plan, error) {
	p, err := newPlan(fields)
	if err != nil {
		return Plan{}, fmt.Errorf("stackencrypt: %w", err)
	}
	return p, nil
}

// newPlan is the one validation both constructors go through; its errors
// name the field, and the caller adds the prefix and, for tags, the type.
func newPlan(fields []FieldPlan) (Plan, error) {
	if len(fields) == 0 {
		return Plan{}, errors.New("a plan needs at least one field")
	}
	d := &planData{fields: make([]planField, 0, len(fields))}
	seenField := make(map[string]bool, len(fields))
	seenName := make(map[string]bool, len(fields))
	for _, f := range fields {
		if f.Field == "" {
			return Plan{}, errors.New("plan field without a Field name")
		}
		if seenField[f.Field] {
			return Plan{}, fmt.Errorf("plan field %s: the Go field is planned twice", f.Field)
		}
		seenField[f.Field] = true
		if f.Context == "" {
			return Plan{}, fmt.Errorf("plan field %s: a planned field needs a context", f.Field)
		}
		if _, err := PlanContext(f.Context); err != nil {
			return Plan{}, fmt.Errorf("plan field %s: %w", f.Field, err)
		}
		pf := planField{field: f.Field, name: f.Field, context: f.Context}
		if f.Name != "" {
			pf.name = f.Name
		}
		for _, k := range f.Terms {
			if !k.valid() {
				return Plan{}, fmt.Errorf("plan field %s: unknown term kind %s", f.Field, k)
			}
			if slices.Contains(pf.terms, k) {
				return Plan{}, fmt.Errorf("plan field %s: term kind %s given twice", f.Field, k)
			}
			pf.terms = append(pf.terms, k)
		}
		if seenName[pf.name] {
			return Plan{}, fmt.Errorf("two plan fields share the record name %q", pf.name)
		}
		seenName[pf.name] = true
		d.fields = append(d.fields, pf)
	}
	return Plan{d: d}, nil
}

// Fields returns the plan's fields, in order, as they were given to NewPlan
// (Name filled in). A copy: mutating it does not touch the plan.
func (p Plan) Fields() []FieldPlan {
	if p.d == nil {
		return nil
	}
	out := make([]FieldPlan, len(p.d.fields))
	for i, f := range p.d.fields {
		out[i] = FieldPlan{Field: f.field, Name: f.name, Context: f.context, Terms: slices.Clone(f.terms)}
	}
	return out
}

var tagPlans sync.Map // reflect.Type → Plan

// PlanFromTags parses (and caches) the plan a struct type's `stash` tags
// describe. This is the plan the record calls use when no WithPlan option
// is given. The tag grammar is checked here; what the fields mean is
// checked by the same validation NewPlan runs.
func PlanFromTags(t reflect.Type) (Plan, error) {
	if t == nil {
		return Plan{}, errors.New("stackencrypt: records must be structs, not a nil type")
	}
	if cached, ok := tagPlans.Load(t); ok {
		return cached.(Plan), nil
	}
	if t.Kind() != reflect.Struct {
		return Plan{}, fmt.Errorf("stackencrypt: records must be structs, not %s", t)
	}
	var fields []FieldPlan
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag, ok := f.Tag.Lookup("stash")
		if !ok || tag == "-" || tag == "plain" {
			continue
		}
		pf := FieldPlan{Field: f.Name, Name: f.Name}
		for _, opt := range strings.Split(tag, ",") {
			key, value, _ := strings.Cut(opt, "=")
			switch key {
			case "context":
				pf.Context = value
			case "name":
				if value == "" {
					return Plan{}, fmt.Errorf("stackencrypt: field %s.%s: name must not be empty", t, f.Name)
				}
				pf.Name = value
			case "index":
				for _, k := range strings.Split(value, ";") {
					kind, ok := parseTermKind(k)
					if !ok {
						return Plan{}, fmt.Errorf("stackencrypt: field %s.%s: unknown term kind %q", t, f.Name, k)
					}
					pf.Terms = append(pf.Terms, kind)
				}
			default:
				return Plan{}, fmt.Errorf("stackencrypt: field %s.%s: unknown stash tag option %q", t, f.Name, opt)
			}
		}
		fields = append(fields, pf)
	}
	if len(fields) == 0 {
		return Plan{}, fmt.Errorf("stackencrypt: %s has no fields tagged for encryption", t)
	}
	plan, err := newPlan(fields)
	if err != nil {
		return Plan{}, fmt.Errorf("stackencrypt: %s: %w", t, err)
	}
	tagPlans.Store(t, plan)
	return plan, nil
}

// fieldPlan is one planned field bound to a struct type: the plan's field
// resolved to its index.
type fieldPlan struct {
	index   int    // struct field index
	name    string // wire name
	context string // the field's own context part
	outputs []string
}

// Validate checks that the plan binds to t: every planned field is an
// exported, direct field of the struct type. The record calls make the
// same check on every call and fail with the same error; this is for a
// caller that builds a plan at startup for a type it knows, so a field the
// type does not have is reported then rather than at the first write. The
// zero Plan is the type's own tags, and PlanFromTags validates those.
func (p Plan) Validate(t reflect.Type) error {
	if p.d == nil {
		_, err := PlanFromTags(t)
		return err
	}
	if t == nil {
		return errors.New("stackencrypt: records must be structs, not a nil type")
	}
	_, err := p.bind(t)
	return err
}

// bind resolves the plan's fields against a struct type. Not cached: a
// name lookup per field is far below the cost of the call it precedes, and
// a cache keyed by plan would grow with every plan a caller ever built.
func (p Plan) bind(t reflect.Type) ([]fieldPlan, error) {
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("stackencrypt: records must be structs, not %s", t)
	}
	bound := make([]fieldPlan, len(p.d.fields))
	for i, f := range p.d.fields {
		sf, ok := t.FieldByName(f.field)
		if !ok || !sf.IsExported() || len(sf.Index) != 1 {
			return nil, fmt.Errorf("stackencrypt: plan field %s is not an exported field of %s", f.field, t)
		}
		bound[i] = fieldPlan{index: sf.Index[0], name: f.name, context: f.context, outputs: f.outputs()}
	}
	return bound, nil
}

// planFor binds the plan a record call runs under: the option's, or the
// struct's tags.
func planFor(t reflect.Type, o recordOptions) ([]fieldPlan, error) {
	p := o.plan
	if p.d == nil {
		var err error
		if p, err = PlanFromTags(t); err != nil {
			return nil, err
		}
	}
	return p.bind(t)
}

// planValue renders the plan object for the guest, each field's context
// extended by the options.
func planValue(plan []fieldPlan, opts recordOptions) (vcvalue.Object, error) {
	out := make(vcvalue.Object, 0, len(plan))
	for _, f := range plan {
		ctx, err := PlanContext(f.context)
		if err != nil {
			return nil, err
		}
		if ctx, err = extend(ctx, opts.extension); err != nil {
			return nil, err
		}
		outputs := make([]any, len(f.outputs))
		for i, o := range f.outputs {
			outputs[i] = o
		}
		out = append(out, vcvalue.Field{Key: f.name, Value: vcvalue.Object{
			{Key: "context", Value: ctx.value()},
			{Key: "outputs", Value: outputs},
		}})
	}
	return out, nil
}

// PlanContext is the context a [FieldPlan] whose Context is s binds:
// "table/column" as the two-part context [table, column], anything without
// a "/" as one part. A [Cipher.Term] probe for a planned field is built
// with it, so the probe and the field cannot spell their context apart:
//
//	email, err := stackencrypt.PlanContext("users/email")
//	if err != nil { ... }
//	probe, err := cipher.Term(ctx, "bob@example.com", email, stackencrypt.Equality)
func PlanContext(s string) (Context, error) {
	table, column, paired := strings.Cut(s, "/")
	if !paired {
		return NewContext(s)
	}
	if table == "" || column == "" || strings.Contains(column, "/") {
		return Context{}, fmt.Errorf("context %q: give one part, or a table and a column as \"<table>/<column>\"", s)
	}
	ctx, err := NewContext(table)
	if err != nil {
		return Context{}, err
	}
	return ctx.With(column)
}

func applyOptions(opts []RecordOption) recordOptions {
	var o recordOptions
	for _, opt := range opts {
		opt.applyRecord(&o)
	}
	return o
}

// EncryptRecords seals every row of a slice of structs (or a pointer to
// one) per the struct's `stash` tags, or per [WithPlan]: all rows and
// fields from batched ZeroKMS key requests (one per 500 sealed fields),
// terms derived under this keyset's index key. One EncryptedRecord per
// row, in order.
func (cph *Cipher) EncryptRecords(ctx context.Context, rows any, opts ...RecordOption) ([]EncryptedRecord, error) {
	v := reflect.Indirect(reflect.ValueOf(rows))
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return nil, fmt.Errorf("stackencrypt: EncryptRecords takes a slice of structs, not %T", rows)
	}
	o := applyOptions(opts)
	plan, err := planFor(v.Type().Elem(), o)
	if err != nil {
		return nil, err
	}
	source := make([]any, v.Len())
	for i := range source {
		source[i] = sourceRow(v.Index(i), plan)
	}
	tree, err := cph.encryptRecords(ctx, plan, source, o)
	if err != nil {
		return nil, err
	}
	items, ok := tree.([]any)
	if !ok || len(items) != v.Len() {
		return nil, fmt.Errorf("%w: record batch came back as %T", ErrInternal, tree)
	}
	out := make([]EncryptedRecord, len(items))
	for i, item := range items {
		if out[i], err = encryptedRecordOf(item); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// EncryptRecord seals one struct (or a pointer to one) per its `stash`
// tags, or per [WithPlan]; see EncryptRecords.
func (cph *Cipher) EncryptRecord(ctx context.Context, row any, opts ...RecordOption) (EncryptedRecord, error) {
	v := reflect.Indirect(reflect.ValueOf(row))
	if !v.IsValid() {
		return nil, fmt.Errorf("stackencrypt: EncryptRecord takes a struct, not %T", row)
	}
	o := applyOptions(opts)
	plan, err := planFor(v.Type(), o)
	if err != nil {
		return nil, err
	}
	tree, err := cph.encryptRecords(ctx, plan, sourceRow(v, plan), o)
	if err != nil {
		return nil, err
	}
	return encryptedRecordOf(tree)
}

func sourceRow(row reflect.Value, plan []fieldPlan) vcvalue.Object {
	out := make(vcvalue.Object, 0, len(plan))
	for _, f := range plan {
		out = append(out, vcvalue.Field{Key: f.name, Value: row.Field(f.index).Interface()})
	}
	return out
}

func (cph *Cipher) encryptRecords(ctx context.Context, plan []fieldPlan, source any, o recordOptions) (any, error) {
	planObj, err := planValue(plan, o)
	if err != nil {
		return nil, err
	}
	encodedSource, err := vcffi.Marshal(source)
	if err != nil {
		return nil, err
	}
	defer wipe(encodedSource)
	encodedPlan, err := vcffi.Marshal(planObj)
	if err != nil {
		return nil, err
	}
	opts, err := vcffi.Marshal(options(cph.keyset))
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.encryptRecord, buf(encodedSource), buf(encodedPlan), buf(opts))
	})
	if err != nil {
		return nil, err
	}
	defer wipe(out)
	return unmarshalCipherText(out)
}

// encryptedRecordOf lifts one decoded record node into an EncryptedRecord.
func encryptedRecordOf(node any) (EncryptedRecord, error) {
	fields, ok := node.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: record came back as %T", ErrInternal, node)
	}
	rec := make(EncryptedRecord, len(fields))
	for name, outputs := range fields {
		om, ok := outputs.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: field %q came back as %T", ErrInternal, name, outputs)
		}
		var f EncryptedField
		for key, out := range om {
			if key == "c" {
				f.Ciphertext = out
				continue
			}
			term, err := termBytes(out)
			if err != nil {
				return nil, fmt.Errorf("%w: field %q output %q: %v", ErrInternal, name, key, err)
			}
			switch key {
			case "eq":
				f.Equality = term
			case "match":
				f.Match = term
			case "ore":
				f.Ore = term
			case "ope":
				f.Ope = term
			default:
				return nil, fmt.Errorf("%w: field %q has unknown output %q", ErrInternal, name, key)
			}
		}
		rec[name] = f
	}
	return rec, nil
}

// termBytes unwraps a term node: a passthrough carrying the term's bytes.
func termBytes(node any) ([]byte, error) {
	plain, ok := node.(vcvalue.Plain)
	if !ok {
		return nil, fmt.Errorf("term node is %T, not a passthrough", node)
	}
	b, ok := plain.V.([]byte)
	if !ok {
		return nil, fmt.Errorf("term payload is %T, not bytes", plain.V)
	}
	return b, nil
}

// DecryptRecords opens records produced by EncryptRecords under this keyset
// (a record from another keyset is ErrForeignKeyset) into out, a pointer to
// a slice of the same struct type, one element per record. Only the sealed
// outputs participate; terms are one-way. Fields the plan does not name are
// left as they are: when the slice already holds one row per record, each
// row keeps its other fields; otherwise it is replaced by a fresh slice.
// Nothing is written unless every record decodes.
func (cph *Cipher) DecryptRecords(ctx context.Context, records []EncryptedRecord, out any, opts ...RecordOption) error {
	return cph.client.decryptRecords(ctx, cph.keyset, records, out, opts)
}

// DecryptRecord opens one record into out, a pointer to a struct; see
// DecryptRecords. Fields the plan does not name keep their values, and
// nothing is written unless every planned field decodes.
func (cph *Cipher) DecryptRecord(ctx context.Context, record EncryptedRecord, out any, opts ...RecordOption) error {
	return cph.client.decryptRecord(ctx, cph.keyset, record, out, opts)
}

func (c *Client) decryptRecords(ctx context.Context, sel KeysetSelector, records []EncryptedRecord, out any, opts []RecordOption) error {
	ptr := reflect.ValueOf(out)
	if ptr.Kind() != reflect.Pointer || ptr.IsNil() || ptr.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("stackencrypt: DecryptRecords writes into a pointer to a slice of structs, not %T", out)
	}
	o := applyOptions(opts)
	plan, err := planFor(ptr.Elem().Type().Elem(), o)
	if err != nil {
		return err
	}
	tree := make([]any, len(records))
	for i, rec := range records {
		if tree[i], err = recordTree(rec, plan); err != nil {
			return err
		}
	}
	values, err := c.decryptRecordTree(ctx, sel, plan, tree, o)
	if err != nil {
		return err
	}
	items, ok := values.([]any)
	if !ok || len(items) != len(records) {
		return fmt.Errorf("%w: record batch decrypted as %T", ErrInternal, values)
	}
	return commitRecords(ptr.Elem(), items, plan)
}

// commitRecords writes decrypted records into a slice value, atomically:
// the rows are assembled in a scratch slice — copies of the existing rows
// when there is one per record, zero rows otherwise — and stored only once
// every record has been assigned.
func commitRecords(slice reflect.Value, items []any, plan []fieldPlan) error {
	scratch := reflect.MakeSlice(slice.Type(), len(items), len(items))
	if slice.Len() == len(items) {
		reflect.Copy(scratch, slice)
	}
	for i, item := range items {
		if err := assignRecord(scratch.Index(i), item, plan); err != nil {
			return err
		}
	}
	slice.Set(scratch)
	return nil
}

// commitRecord writes one decrypted record into a struct value, atomically:
// a copy takes the planned fields and replaces the original only once
// every one of them has been assigned.
func commitRecord(target reflect.Value, item any, plan []fieldPlan) error {
	scratch := reflect.New(target.Type()).Elem()
	scratch.Set(target)
	if err := assignRecord(scratch, item, plan); err != nil {
		return err
	}
	target.Set(scratch)
	return nil
}

func (c *Client) decryptRecord(ctx context.Context, sel KeysetSelector, record EncryptedRecord, out any, opts []RecordOption) error {
	ptr := reflect.ValueOf(out)
	if ptr.Kind() != reflect.Pointer || ptr.IsNil() || ptr.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("stackencrypt: DecryptRecord writes into a pointer to a struct, not %T", out)
	}
	o := applyOptions(opts)
	plan, err := planFor(ptr.Elem().Type(), o)
	if err != nil {
		return err
	}
	tree, err := recordTree(record, plan)
	if err != nil {
		return err
	}
	value, err := c.decryptRecordTree(ctx, sel, plan, tree, o)
	if err != nil {
		return err
	}
	return commitRecord(ptr.Elem(), value, plan)
}

// recordTree renders the ciphertext tree the guest opens: per planned
// field, its "c" output. Terms are not sent.
func recordTree(rec EncryptedRecord, plan []fieldPlan) (map[string]any, error) {
	tree := make(map[string]any, len(plan))
	for _, f := range plan {
		field, ok := rec[f.name]
		if !ok || field.Ciphertext == nil {
			return nil, fmt.Errorf("stackencrypt: record has no ciphertext for field %q", f.name)
		}
		tree[f.name] = map[string]any{"c": field.Ciphertext}
	}
	return tree, nil
}

func (c *Client) decryptRecordTree(ctx context.Context, sel KeysetSelector, plan []fieldPlan, tree any, o recordOptions) (any, error) {
	planObj, err := planValue(plan, o)
	if err != nil {
		return nil, err
	}
	encodedTree, err := marshalCipherText(tree)
	if err != nil {
		return nil, err
	}
	encodedPlan, err := vcffi.Marshal(planObj)
	if err != nil {
		return nil, err
	}
	opts, err := vcffi.Marshal(options(sel))
	if err != nil {
		return nil, err
	}
	out, err := c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.decryptRecord, buf(encodedTree), buf(encodedPlan), buf(opts))
	})
	if err != nil {
		return nil, err
	}
	defer wipe(out)
	return vcffi.Unmarshal(out)
}

// assignRecord writes a decrypted record (a vcvalue.Object of the plan's
// fields) into a struct value.
func assignRecord(target reflect.Value, value any, plan []fieldPlan) error {
	obj, ok := value.(vcvalue.Object)
	if !ok {
		return fmt.Errorf("%w: record decrypted as %T", ErrInternal, value)
	}
	byName := make(map[string]any, len(obj))
	for _, f := range obj {
		byName[f.Key] = f.Value
	}
	for _, f := range plan {
		v, ok := byName[f.name]
		if !ok {
			return fmt.Errorf("%w: decrypted record lacks field %q", ErrInternal, f.name)
		}
		if err := assignField(target.Field(f.index), v); err != nil {
			return fmt.Errorf("stackencrypt: field %q: %w", f.name, err)
		}
	}
	return nil
}

var errUnassignable = errors.New("cannot assign decrypted value")

// assignField sets a struct field from a decoded value, converting within
// a numeric family when the value fits and refusing anything lossy. A
// decoded nil (a sealed none) is accepted only by a field that can hold
// one — a pointer, slice, map or interface — never as a zero scalar.
func assignField(field reflect.Value, v any) error {
	if v == nil {
		switch field.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
			field.Set(reflect.Zero(field.Type()))
			return nil
		default:
			return fmt.Errorf("%w: nil into %s", errUnassignable, field.Type())
		}
	}
	if field.Kind() == reflect.Pointer {
		elem := reflect.New(field.Type().Elem())
		if err := assignField(elem.Elem(), v); err != nil {
			return err
		}
		field.Set(elem)
		return nil
	}
	rv := reflect.ValueOf(v)
	if rv.Type().AssignableTo(field.Type()) {
		field.Set(rv)
		return nil
	}
	// A defined type over the same kind (type Flag bool, type Raw []byte)
	// converts without loss.
	if rv.Kind() == field.Kind() && rv.Type().ConvertibleTo(field.Type()) {
		switch field.Kind() {
		case reflect.Bool, reflect.String, reflect.Slice:
			field.Set(rv.Convert(field.Type()))
			return nil
		}
	}
	switch field.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var n int64
		switch x := v.(type) {
		case int32:
			n = int64(x)
		case int64:
			n = x
		default:
			return fmt.Errorf("%w: %T into %s", errUnassignable, v, field.Type())
		}
		if field.OverflowInt(n) {
			return fmt.Errorf("%w: %d overflows %s", errUnassignable, n, field.Type())
		}
		field.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		var n uint64
		switch x := v.(type) {
		case uint32:
			n = uint64(x)
		case uint64:
			n = x
		default:
			return fmt.Errorf("%w: %T into %s", errUnassignable, v, field.Type())
		}
		if field.OverflowUint(n) {
			return fmt.Errorf("%w: %d overflows %s", errUnassignable, n, field.Type())
		}
		field.SetUint(n)
	case reflect.Float32, reflect.Float64:
		var f float64
		switch x := v.(type) {
		case float32:
			f = float64(x)
		case float64:
			f = x
		default:
			return fmt.Errorf("%w: %T into %s", errUnassignable, v, field.Type())
		}
		if field.OverflowFloat(f) {
			return fmt.Errorf("%w: %v overflows %s", errUnassignable, f, field.Type())
		}
		// Narrowing must be exact: a float64 that float32 cannot represent
		// would silently round. NaN is its own case, never equal to itself.
		if field.Kind() == reflect.Float32 && float64(float32(f)) != f && f == f {
			return fmt.Errorf("%w: %v is not representable as %s", errUnassignable, f, field.Type())
		}
		field.SetFloat(f)
	case reflect.String:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%w: %T into %s", errUnassignable, v, field.Type())
		}
		field.SetString(s)
	case reflect.Bool:
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("%w: %T into %s", errUnassignable, v, field.Type())
		}
		field.SetBool(b)
	default:
		return fmt.Errorf("%w: %T into %s", errUnassignable, v, field.Type())
	}
	return nil
}
