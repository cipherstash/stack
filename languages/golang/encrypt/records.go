package encrypt

import (
	"context"
	"errors"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The record path: what generated code calls through encrypt/gensupport.
// The three methods take and return the internal record types, so a program
// cannot call them with anything but what a generated declaration lowered
// to; the generated functions (users.Encrypt, users.Decrypt, users.Fields)
// are the API. Every call is one guest call, and one batched ZeroKMS request
// however many rows it carries (one request per 500 sealed leaves).

// Decrypter opens records: a *Cipher, which refuses a record sealed under
// another keyset before any key is retrieved, or a *Client, which opens each
// record under the keyset that sealed it. Generated Decrypt functions take
// one. Its method is for generated code; a program does not call it.
type Decrypter interface {
	Open(ctx context.Context, plan *record.Plan, records []record.Sealed) ([]record.Source, error)
}

// Seal encrypts rows under the plan, through this cipher's keyset and with
// its extension: the sealed fields of every row in one request, in order.
// For generated code.
func (cph *Cipher) Seal(ctx context.Context, plan *record.Plan, rows []record.Source) ([]record.Sealed, error) {
	p, err := cph.plan(plan)
	if err != nil {
		return nil, err
	}
	source := make([]any, len(rows))
	for i, row := range rows {
		source[i], err = sourceRow(p, row)
		if err != nil {
			return nil, fmt.Errorf("%w: row %d: %v", ErrEncoding, i, err)
		}
	}
	encodedSource, err := vcffi.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	// The source is plaintext: its transport copy is wiped once it is in
	// the guest, and the guest wipes its own copy before it returns.
	defer wipe(encodedSource)
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
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
	tree, err := unmarshalCipherText(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	items, ok := tree.([]any)
	if !ok || len(items) != len(rows) {
		return nil, fmt.Errorf("%w: %d rows came back as %T", ErrInternal, len(rows), tree)
	}
	sealed := make([]record.Sealed, len(items))
	for i, item := range items {
		if sealed[i], err = sealedOf(p, item); err != nil {
			return nil, fmt.Errorf("%w: row %d: %v", ErrInternal, i, err)
		}
	}
	return sealed, nil
}

// Open decrypts records sealed under the plan: every row in one request,
// in order. A record from another keyset is [ErrForeignKeyset]. For
// generated code.
func (cph *Cipher) Open(ctx context.Context, plan *record.Plan, records []record.Sealed) ([]record.Source, error) {
	p, err := cph.plan(plan)
	if err != nil {
		return nil, err
	}
	return cph.client.open(ctx, cph.keyset, p, records)
}

// Derive derives one index term for one value of a field, under the plan's
// context for that field and this cipher's extension: the term a query
// compares against the stored one. For generated code.
func (cph *Cipher) Derive(ctx context.Context, plan *record.Plan, field string, output record.Output, value any) ([]byte, error) {
	p, err := cph.plan(plan)
	if err != nil {
		return nil, err
	}
	f := p.Field(field)
	if f == nil {
		return nil, fmt.Errorf("%w: the plan has no field %q", ErrEncoding, field)
	}
	code, ok := termKindCode(output)
	if !ok {
		return nil, fmt.Errorf("%w: field %q: no term %q", ErrEncoding, field, output)
	}
	declared := false
	for _, o := range f.Outputs {
		declared = declared || o == output
	}
	if !declared {
		return nil, fmt.Errorf("%w: field %q declares no %q index", ErrEncoding, field, output)
	}
	encodedValue, err := vcffi.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	// The probe value is plaintext: its transport copy is wiped once it is
	// in the guest.
	defer wipe(encodedValue)
	encodedContext, err := vcffi.Marshal(p.FieldContext(*f))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	opts, err := vcffi.Marshal(options(cph.keyset))
	if err != nil {
		return nil, err
	}
	return cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.term, buf(encodedValue), buf(encodedContext), scalar(uint64(code)), buf(opts))
	})
}

// Open decrypts records sealed under the plan by any keyset of this client:
// each record is opened under the keyset that sealed it, with one request
// per keyset. For generated code.
func (c *Client) Open(ctx context.Context, plan *record.Plan, records []record.Sealed) ([]record.Source, error) {
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return c.open(ctx, anyKeyset{}, plan, records)
}

// plan is the declaration's plan with this cipher's extension, checked.
func (cph *Cipher) plan(plan *record.Plan) (*record.Plan, error) {
	if cph.err != nil {
		return nil, cph.err
	}
	if plan == nil {
		return nil, fmt.Errorf("%w: no plan", ErrEncoding)
	}
	p := *plan
	p.Extension = append(append([]any(nil), plan.Extension...), cph.extension...)
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return &p, nil
}

// sourceRow renders one row for the guest: the plan's fields, in plan order,
// each with its value. Fail closed in both directions: a field with no value
// and a value with no field are both refused before anything is sent.
func sourceRow(p *record.Plan, row record.Source) (vcvalue.Object, error) {
	if len(row) != len(p.Fields) {
		for name := range row {
			if p.Field(name) == nil {
				return nil, fmt.Errorf("the plan has no field %q", name)
			}
		}
	}
	out := make(vcvalue.Object, 0, len(p.Fields))
	for _, f := range p.Fields {
		v, ok := row[f.Name]
		if !ok {
			return nil, fmt.Errorf("no value for field %q", f.Name)
		}
		out = append(out, vcvalue.Field{Key: f.Name, Value: v})
	}
	return out, nil
}

// sealedOf lifts one decoded record node into the per-field outputs.
func sealedOf(p *record.Plan, node any) (record.Sealed, error) {
	fields, ok := node.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("record came back as %T", node)
	}
	sealed := make(record.Sealed, len(fields))
	for name, outputs := range fields {
		if p.Field(name) == nil {
			return nil, fmt.Errorf("the engine returned a field %q the plan does not name", name)
		}
		om, ok := outputs.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("field %q came back as %T", name, outputs)
		}
		var o record.Outputs
		for key, out := range om {
			if key == string(record.Ciphertext) {
				leaf, ok := out.(Ciphertext)
				if !ok {
					return nil, fmt.Errorf("field %q: the ciphertext is a %T, not one leaf", name, out)
				}
				o.Ciphertext = leaf
				continue
			}
			term, err := termBytes(out)
			if err != nil {
				return nil, fmt.Errorf("field %q output %q: %v", name, key, err)
			}
			if o.Terms == nil {
				o.Terms = map[record.Output][]byte{}
			}
			o.Terms[record.Output(key)] = term
		}
		sealed[name] = o
	}
	for _, f := range p.Fields {
		if _, ok := sealed[f.Name]; !ok {
			return nil, fmt.Errorf("the engine returned no outputs for field %q", f.Name)
		}
	}
	return sealed, nil
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

// errNoCiphertext is a stored record missing a field the plan seals.
var errNoCiphertext = errors.New("encrypt: the record has no ciphertext for a sealed field")

func (c *Client) open(ctx context.Context, sel KeysetSelector, p *record.Plan, records []record.Sealed) ([]record.Source, error) {
	trees := make([]any, len(records))
	for i, rec := range records {
		tree := make(map[string]any, len(p.Fields))
		for _, f := range p.Fields {
			hasCiphertext := false
			for _, o := range f.Outputs {
				hasCiphertext = hasCiphertext || o == record.Ciphertext
			}
			if !hasCiphertext {
				continue
			}
			outputs, ok := rec[f.Name]
			if !ok || outputs.Ciphertext == nil {
				return nil, fmt.Errorf("%w: row %d, field %q", errNoCiphertext, i, f.Name)
			}
			tree[f.Name] = map[string]any{string(record.Ciphertext): Ciphertext(outputs.Ciphertext)}
		}
		trees[i] = tree
	}
	encodedTree, err := marshalCipherText(trees)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
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
	// The output is plaintext: decode, then wipe the transport copy.
	defer wipe(out)
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	items, ok := decoded.([]any)
	if !ok || len(items) != len(records) {
		return nil, fmt.Errorf("%w: %d records came back as %T", ErrInternal, len(records), decoded)
	}
	sources := make([]record.Source, len(items))
	for i, item := range items {
		obj, ok := item.(vcvalue.Object)
		if !ok {
			return nil, fmt.Errorf("%w: record %d decrypted as %T", ErrInternal, i, item)
		}
		src := make(record.Source, len(obj))
		for _, f := range obj {
			src[f.Key] = f.Value
		}
		for _, f := range p.Fields {
			if _, ok := src[f.Name]; !ok {
				// An index-only field has no ciphertext to open and comes
				// back as nothing; every sealed field must.
				for _, o := range f.Outputs {
					if o == record.Ciphertext {
						return nil, fmt.Errorf("%w: record %d lacks field %q", ErrInternal, i, f.Name)
					}
				}
			}
		}
		sources[i] = src
	}
	return sources, nil
}
