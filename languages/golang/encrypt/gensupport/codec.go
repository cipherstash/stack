package gensupport

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Values is a struct's field values by declared name: what Source gives and
// what Value reads. Passthrough fields are in it too.
type Values map[string]any

// Output is what one field became: the passthrough value, or the ciphertext
// and each term the field declares. EQL is the EQL value of an encrypt_into
// field, once the engine produces one.
type Output struct {
	Value      any
	Ciphertext encrypt.Ciphertext
	Equality   encrypt.EqualityTerm
	Match      encrypt.MatchTerm
	Ore        encrypt.OreTerm
	Ope        encrypt.OpeTerm
	JSON       encrypt.JSONTerm
	EQL        []byte
}

// Record is one record's fields by declared name, as Seal reads it and Open
// writes it.
type Record map[string]Output

// Generated is what a generated file gives the library for one type: the
// declaration, and the four conversions between the plaintext type P, the
// encrypted type E and the data the engine reads and returns. A file writes
// these without reflection: each is a function over named fields.
type Generated[P, E any] struct {
	// TypeName is how notices print the type: "User" or "crm.Contact".
	TypeName string
	// Declaration is the struct's tags as data.
	Declaration Declaration
	// PrintsPlaintext is true when P has no String and LogValue methods, so
	// the running program warns once that P prints its sealed fields.
	PrintsPlaintext bool
	// Unexported are the unexported fields with no tag, which are neither
	// encrypted nor stored; the running program warns once.
	Unexported []string
	// Source reads every declared field of a value.
	Source func(P) Values
	// Seal builds the encrypted value from the engine's outputs.
	Seal func(Record) (E, error)
	// Open reads the engine's inputs from an encrypted value.
	Open func(E) Record
	// Value builds the plaintext from the opened fields.
	Value func(E, Values) (P, error)
}

// Codec encrypts and decrypts one generated type.
type Codec[P, E any] struct {
	g      Generated[P, E]
	plan   *record.Plan
	err    error
	notice sync.Once
}

// New builds the codec for a generated type. A declaration the engine cannot
// run is reported by the first call, not here: nothing in this package
// panics, and a package-level var cannot return an error.
func New[P, E any](g Generated[P, E]) *Codec[P, E] {
	c := &Codec[P, E]{g: g}
	c.plan, c.err = g.Declaration.plan()
	if c.err == nil && (g.Source == nil || g.Seal == nil || g.Open == nil || g.Value == nil) {
		c.err = fmt.Errorf("gensupport: %s: the generated file is incomplete", g.TypeName)
	}
	return c
}

func (c *Codec[P, E]) notices() {
	c.notice.Do(func() {
		NoticeUntagged(c.g.TypeName, c.g.Unexported)
		if c.g.PrintsPlaintext {
			NoticePrintsPlaintext(c.g.TypeName)
		}
	})
}

// Encrypt seals every value, with one request for each 500 sealed values. The result has one element for
// each value, in the same order.
func (c *Codec[P, E]) Encrypt(ctx context.Context, cipher *encrypt.Cipher, values []P) ([]E, error) {
	c.notices()
	if c.err != nil {
		return nil, c.err
	}
	if cipher == nil {
		return nil, fmt.Errorf("gensupport: %s: Encrypt needs a cipher", c.g.TypeName)
	}
	rows := make([]record.Source, len(values))
	passthrough := make([]map[string]any, len(values))
	for i, v := range values {
		vals := c.g.Source(v)
		if vals == nil {
			return nil, fmt.Errorf("gensupport: %s: value %d is nil", c.g.TypeName, i)
		}
		row, keep, err := c.split(vals)
		if err != nil {
			return nil, fmt.Errorf("gensupport: %s: value %d: %w", c.g.TypeName, i, err)
		}
		if c.g.Declaration.opaque {
			if row[OpaqueField], err = opaqueBytes(row[OpaqueField]); err != nil {
				return nil, fmt.Errorf("gensupport: %s: value %d: %w", c.g.TypeName, i, err)
			}
		}
		rows[i], passthrough[i] = row, keep
	}
	sealed, err := cipher.Seal(ctx, c.plan, rows)
	if err != nil {
		return nil, err
	}
	out := make([]E, len(values))
	for i, s := range sealed {
		rec := make(Record, len(c.g.Declaration.fields))
		for name, v := range passthrough[i] {
			rec[name] = Output{Value: v}
		}
		for name, o := range s {
			rec[name] = outputOf(o)
		}
		if out[i], err = c.g.Seal(rec); err != nil {
			return nil, fmt.Errorf("gensupport: %s: value %d: %w", c.g.TypeName, i, err)
		}
	}
	return out, nil
}

// Decrypt opens every value, with one request for each 500 sealed values.
func (c *Codec[P, E]) Decrypt(ctx context.Context, d encrypt.Decrypter, encrypted []E) ([]P, error) {
	c.notices()
	if c.err != nil {
		return nil, c.err
	}
	if d == nil {
		return nil, fmt.Errorf("gensupport: %s: Decrypt needs a Cipher or a Client", c.g.TypeName)
	}
	records := make([]record.Sealed, len(encrypted))
	passthrough := make([]map[string]any, len(encrypted))
	for i, e := range encrypted {
		rec := c.g.Open(e)
		records[i] = make(record.Sealed, len(c.plan.Fields))
		passthrough[i] = map[string]any{}
		for _, f := range c.g.Declaration.fields {
			o, ok := rec[f.name]
			switch {
			case f.verb == verbOmit:
				continue
			case !ok:
				return nil, fmt.Errorf("gensupport: %s: value %d: Open gave no field %q", c.g.TypeName, i, f.name)
			case f.verb == verbContextField:
				label, isString := o.Value.(string)
				if !isString {
					return nil, fmt.Errorf("gensupport: %s: value %d: the context field %q holds a %T, not a string", c.g.TypeName, i, f.name, o.Value)
				}
				records[i][f.name] = record.Outputs{Context: label}
			case f.sealed():
				records[i][f.name] = record.Outputs{Ciphertext: o.Ciphertext}
			default:
				passthrough[i][f.name] = o.Value
			}
		}
	}
	sources, err := d.Open(ctx, c.plan, records)
	if err != nil {
		return nil, err
	}
	out := make([]P, len(encrypted))
	for i, src := range sources {
		vals := make(Values, len(c.g.Declaration.fields))
		for name, v := range passthrough[i] {
			vals[name] = v
		}
		for name, v := range src {
			vals[name] = v
		}
		if out[i], err = c.g.Value(encrypted[i], vals); err != nil {
			return nil, fmt.Errorf("gensupport: %s: value %d: %w", c.g.TypeName, i, err)
		}
	}
	return out, nil
}

// split sorts a value's fields into what crosses the binding and what stays:
// every declared field must be present and nothing else may be.
func (c *Codec[P, E]) split(vals Values) (record.Source, map[string]any, error) {
	row := make(record.Source, len(c.plan.Fields))
	keep := map[string]any{}
	for _, f := range c.g.Declaration.fields {
		if f.verb == verbOmit {
			continue
		}
		v, ok := vals[f.name]
		if !ok {
			return nil, nil, fmt.Errorf("the generated Source gave no field %q", f.name)
		}
		if f.crosses() {
			row[f.name] = v
		} else {
			keep[f.name] = v
		}
	}
	if len(vals) != len(row)+len(keep) {
		for name := range vals {
			if _, ok := row[name]; ok {
				continue
			}
			if _, ok := keep[name]; ok {
				continue
			}
			return nil, nil, fmt.Errorf("the generated Source gave a field %q the declaration does not name", name)
		}
	}
	return row, keep, nil
}

func outputOf(o record.Outputs) Output {
	if o.Context != "" {
		// The context field comes back as the passthrough it is.
		return Output{Value: o.Context}
	}
	out := Output{Ciphertext: o.Ciphertext}
	for k, term := range o.Terms {
		switch k {
		case record.Equality:
			out.Equality = term
		case record.Match:
			out.Match = term
		case record.Ore:
			out.Ore = term
		case record.Ope:
			out.Ope = term
		}
	}
	return out
}

// Passthrough reads a passthrough field from a record, as the Go type the
// struct declares it.
func Passthrough[T any](rec Record, name string) (T, error) {
	o, ok := rec[name]
	if !ok {
		var zero T
		return zero, fmt.Errorf("gensupport: no passthrough field %q", name)
	}
	v, ok := o.Value.(T)
	if !ok {
		var zero T
		if o.Value == nil && any(zero) == nil {
			// A nil interface value asserts to no type. For an interface T
			// it is the value the struct held.
			return zero, nil
		}
		return zero, fmt.Errorf("gensupport: passthrough field %q holds a %T, not a %T", name, o.Value, zero)
	}
	return v, nil
}

// Get reads one opened field as the Go type the struct declares it. A
// passthrough field is the Go value the struct held, whatever its type, and
// comes back as it is. A sealed field comes back from the engine at its
// declared wire kind; Get converts within that kind's family (a uint32 into
// a uint8 that holds it) and refuses anything else, so a value that opens to
// another type is an error and never a silent zero. A defined type over a
// scalar (type Email string) is read at its underlying type and converted by
// the generated code.
func Get[T any](vals Values, name string) (T, error) {
	var out T
	v, ok := vals[name]
	if !ok {
		return out, fmt.Errorf("gensupport: the opened value has no field %q", name)
	}
	if exact, ok := v.(T); ok {
		return exact, nil
	}
	if v == nil && any(out) == nil {
		// A nil interface value asserts to no type. For an interface T,
		// such as a passthrough error or any, it is the value the struct
		// held.
		return out, nil
	}
	if err := convert(v, &out); err != nil {
		return out, fmt.Errorf("gensupport: field %q: %w: %w", name, encrypt.ErrEncoding, err)
	}
	return out, nil
}

// Records wraps a codec with a model's conversions, for separate columns:
// EncryptRows and DecryptRows return and take the model.
func Records[P, E, R any](codec *Codec[P, E], to func(E) R, from func(R) E) *RecordsCodec[P, R] {
	return &RecordsCodec[P, R]{
		encrypt: func(ctx context.Context, c *encrypt.Cipher, values []P) ([]R, error) {
			es, err := codec.Encrypt(ctx, c, values)
			if err != nil {
				return nil, err
			}
			rs := make([]R, len(es))
			for i, e := range es {
				rs[i] = to(e)
			}
			return rs, nil
		},
		decrypt: func(ctx context.Context, d encrypt.Decrypter, rows []R) ([]P, error) {
			es := make([]E, len(rows))
			for i, r := range rows {
				es[i] = from(r)
			}
			return codec.Decrypt(ctx, d, es)
		},
	}
}

// RecordsCodec encrypts into and decrypts from a model.
type RecordsCodec[P, R any] struct {
	encrypt func(context.Context, *encrypt.Cipher, []P) ([]R, error)
	decrypt func(context.Context, encrypt.Decrypter, []R) ([]P, error)
}

// Encrypt seals every value into a model row, with one request for each 500 sealed values.
func (c *RecordsCodec[P, R]) Encrypt(ctx context.Context, cipher *encrypt.Cipher, values []P) ([]R, error) {
	return c.encrypt(ctx, cipher, values)
}

// Decrypt opens every model row, with one request for each 500 sealed values.
func (c *RecordsCodec[P, R]) Decrypt(ctx context.Context, d encrypt.Decrypter, rows []R) ([]P, error) {
	return c.decrypt(ctx, d, rows)
}

// opaqueBytes is an opaque struct's fields as the one value the engine
// seals: a JSON document of the generated shape struct, so the struct is one
// column and every field type encoding/json round-trips comes back as it
// was.
func opaqueBytes(fields any) ([]byte, error) {
	encoded, err := json.Marshal(fields)
	if err != nil {
		// encoding/json refuses NaN and the infinities, which a sealed float
		// field outside an opaque struct accepts.
		// Its error is not wrapped: encoding/json's text quotes the value.
		return nil, fmt.Errorf("%w: the opaque value does not encode as JSON (NaN, an infinity, or a type encoding/json refuses)", encrypt.ErrEncoding)
	}
	return encoded, nil
}

// Opaque reads an opened opaque value into the generated shape struct: the
// JSON document the engine returned, decoded into the exact Go types the
// struct declares. Generated code calls it from Value.
func Opaque[T any](vals Values, out *T) error {
	v, ok := vals[OpaqueField]
	if !ok {
		return fmt.Errorf("gensupport: the opened value has no field %q", OpaqueField)
	}
	encoded, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("gensupport: %w: the opaque value opened as %T, not bytes", encrypt.ErrEncoding, v)
	}
	if err := json.Unmarshal(encoded, out); err != nil {
		// Its error is not wrapped: encoding/json's text quotes the value.
		return fmt.Errorf("gensupport: %w: the opaque value does not decode into a %T", encrypt.ErrEncoding, *out)
	}
	return nil
}
