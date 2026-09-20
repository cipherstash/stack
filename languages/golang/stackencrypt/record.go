package stackencrypt

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Record plans from struct tags — the Go stand-in for the Rust derive.
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
// Options are comma-separated: `context=<part>` (required for a planned
// field — the field's own context, a string part), `index=<kind>[;<kind>]`
// (eq, match, ore, ope), and `name=<wire name>` (the record key; the Go
// field name otherwise). A field tagged `-` or `plain`, or not tagged at
// all, is not part of the record: it never crosses the boundary, and stays
// the caller's to store. Unexported fields are ignored.
//
// Every planned field is sealed (the `"c"` output) and the plan is built
// once per type. The context each field binds is its tag's part, extended
// by [ExtendContext] parts exactly as the Rust derive extends a field's
// context by the caller's: NewContext(tag).With(p1).With(p2).

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

// RecordOption adjusts how a record call binds its fields.
type RecordOption func(*recordOptions)

type recordOptions struct {
	extension []any
}

// ExtendContext extends every field's context by parts, in order, the way
// the Rust derive extends a field's context by the caller's
// (encrypt_into_with_context): a field tagged context=users/age with
// ExtendContext(uint64(7)) binds ["users/age", 7]. The same extension must
// be given to decrypt the records.
func ExtendContext(parts ...any) RecordOption {
	return func(o *recordOptions) { o.extension = append(o.extension, parts...) }
}

// fieldPlan is one planned struct field.
type fieldPlan struct {
	index   int    // struct field index
	name    string // wire name
	context string // the field's own context part
	outputs []string
}

var plans sync.Map // reflect.Type → []fieldPlan

// planFor parses (and caches) a struct type's plan.
func planFor(t reflect.Type) ([]fieldPlan, error) {
	if cached, ok := plans.Load(t); ok {
		return cached.([]fieldPlan), nil
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("stackencrypt: records must be structs, not %s", t)
	}
	var plan []fieldPlan
	seen := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag, ok := f.Tag.Lookup("stash")
		if !ok || tag == "-" || tag == "plain" {
			continue
		}
		fp := fieldPlan{index: i, name: f.Name, outputs: []string{"c"}}
		for _, opt := range strings.Split(tag, ",") {
			key, value, _ := strings.Cut(opt, "=")
			switch key {
			case "context":
				if value == "" {
					return nil, fmt.Errorf("stackencrypt: field %s.%s: context must not be empty", t, f.Name)
				}
				fp.context = value
			case "name":
				if value == "" {
					return nil, fmt.Errorf("stackencrypt: field %s.%s: name must not be empty", t, f.Name)
				}
				fp.name = value
			case "index":
				for _, k := range strings.Split(value, ";") {
					kind, ok := parseTermKind(k)
					if !ok {
						return nil, fmt.Errorf("stackencrypt: field %s.%s: unknown index kind %q", t, f.Name, k)
					}
					fp.outputs = append(fp.outputs, kind.String())
				}
			default:
				return nil, fmt.Errorf("stackencrypt: field %s.%s: unknown stash tag option %q", t, f.Name, opt)
			}
		}
		if fp.context == "" {
			return nil, fmt.Errorf("stackencrypt: field %s.%s: a planned field needs context=", t, f.Name)
		}
		if seen[fp.name] {
			return nil, fmt.Errorf("stackencrypt: %s: two fields share the record name %q", t, fp.name)
		}
		seen[fp.name] = true
		plan = append(plan, fp)
	}
	if len(plan) == 0 {
		return nil, fmt.Errorf("stackencrypt: %s has no fields tagged for encryption", t)
	}
	plans.Store(t, plan)
	return plan, nil
}

// planValue renders the plan object for the guest, each field's context
// extended by the options.
func planValue(plan []fieldPlan, opts recordOptions) (vcvalue.Object, error) {
	out := make(vcvalue.Object, 0, len(plan))
	for _, f := range plan {
		ctx, err := NewContext(f.context)
		if err != nil {
			return nil, err
		}
		for _, part := range opts.extension {
			if ctx, err = ctx.With(part); err != nil {
				return nil, err
			}
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

func applyOptions(opts []RecordOption) recordOptions {
	var o recordOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// EncryptRecords seals every row of a slice of structs (or a pointer to
// one) per the struct's `stash` tags: all rows and fields from batched
// ZeroKMS key requests (one per 500 sealed fields), terms derived under
// this keyset's index key. One EncryptedRecord per row, in order.
func (cph *Cipher) EncryptRecords(ctx context.Context, rows any, opts ...RecordOption) ([]EncryptedRecord, error) {
	v := reflect.Indirect(reflect.ValueOf(rows))
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return nil, fmt.Errorf("stackencrypt: EncryptRecords takes a slice of structs, not %T", rows)
	}
	plan, err := planFor(v.Type().Elem())
	if err != nil {
		return nil, err
	}
	source := make([]any, v.Len())
	for i := range source {
		source[i] = sourceRow(v.Index(i), plan)
	}
	tree, err := cph.encryptRecords(ctx, plan, source, applyOptions(opts))
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
// tags; see EncryptRecords.
func (cph *Cipher) EncryptRecord(ctx context.Context, row any, opts ...RecordOption) (EncryptedRecord, error) {
	v := reflect.Indirect(reflect.ValueOf(row))
	if !v.IsValid() {
		return nil, fmt.Errorf("stackencrypt: EncryptRecord takes a struct, not %T", row)
	}
	plan, err := planFor(v.Type())
	if err != nil {
		return nil, err
	}
	tree, err := cph.encryptRecords(ctx, plan, sourceRow(v, plan), applyOptions(opts))
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
	elem := ptr.Elem().Type().Elem()
	plan, err := planFor(elem)
	if err != nil {
		return err
	}
	tree := make([]any, len(records))
	for i, rec := range records {
		if tree[i], err = recordTree(rec, plan); err != nil {
			return err
		}
	}
	values, err := c.decryptRecordTree(ctx, sel, plan, tree, applyOptions(opts))
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
	plan, err := planFor(ptr.Elem().Type())
	if err != nil {
		return err
	}
	tree, err := recordTree(record, plan)
	if err != nil {
		return err
	}
	value, err := c.decryptRecordTree(ctx, sel, plan, tree, applyOptions(opts))
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
