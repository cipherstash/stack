package gensupport

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Field is one sealed field's entry in a generated Fields value: it encrypts
// one value of the field, for an update of one column, and derives the
// query term of each operator the field answers. T is the field's Go type.
type Field[T any] struct {
	name string
	plan *record.Plan
	err  error
}

// NewField makes the entry for one sealed field of a declaration.
func NewField[T any](d Declaration, name string) Field[T] {
	f := Field[T]{name: name}
	plan, err := d.plan()
	if err != nil {
		f.err = err
		return f
	}
	rf := plan.Field(name)
	if rf == nil {
		f.err = fmt.Errorf("gensupport: NewField(%q): the declaration seals no such field", name)
		return f
	}
	// One field, its own plan: the label is the same, so the bytes are the
	// same as in a whole record.
	f.plan = &record.Plan{Context: plan.Context, ContextField: plan.ContextField, Fields: []record.Field{*rf}}
	return f
}

// kind is the field's declared kind, as its plan holds it.
func (f Field[T]) kind() Kind {
	if pf := f.plan.Field(f.name); pf != nil {
		return Kind(pf.Kind)
	}
	return Untyped
}

// Encrypt seals one value of the field: its ciphertext and every term it
// declares, in one request.
func (f Field[T]) Encrypt(ctx context.Context, c *encrypt.Cipher, v T) (Output, error) {
	if f.err != nil {
		return Output{}, f.err
	}
	value, err := asKind(f.kind(), v)
	if err != nil {
		return Output{}, fmt.Errorf("gensupport: %s: %w", f.name, err)
	}
	return f.seal(ctx, c, "Encrypt", value)
}

// EncryptNull seals nil for a field that stores nil as a sealed null: a
// ciphertext as long as a value's, and the term every nil of the field
// shares. It is the update that sets one such column to nil, which writing
// SQL NULL is not. A field that stores nil any other way is refused: under
// null=sql nil is SQL NULL, and a field of no null mode has no nil.
func (f Field[T]) EncryptNull(ctx context.Context, c *encrypt.Cipher) (Output, error) {
	if f.err != nil {
		return Output{}, f.err
	}
	if pf := f.plan.Field(f.name); pf == nil || pf.Null != record.SealedNull {
		return Output{}, fmt.Errorf("%w: gensupport: %s: EncryptNull seals nil only for a field that stores it as a sealed null (null=sealed)", encrypt.ErrEncoding, f.name)
	}
	return f.seal(ctx, c, "EncryptNull", nil)
}

// seal seals one value of the field, or nil, through the field's own plan.
func (f Field[T]) seal(ctx context.Context, c *encrypt.Cipher, method string, value any) (Output, error) {
	if c == nil {
		return Output{}, fmt.Errorf("gensupport: %s: %s needs a cipher", f.name, method)
	}
	row := record.Source{f.name: value}
	if f.plan.ContextField != "" {
		// One value of one field has no record to take its context from:
		// the cipher names it, as it does for a query.
		label := c.ContextLabel()
		if label == "" {
			return Output{}, fmt.Errorf("%w: %s: the type takes its context from its field %q, so one value is encrypted through a cipher that names it with Cipher.Context", encrypt.ErrEncoding, f.name, f.plan.ContextField)
		}
		row[f.plan.ContextField] = label
	}
	sealed, err := c.Seal(ctx, f.plan, []record.Source{row})
	if err != nil {
		return Output{}, err
	}
	if len(sealed) != 1 {
		return Output{}, fmt.Errorf("gensupport: %s: one value came back as %d", f.name, len(sealed))
	}
	return outputOf(sealed[0][f.name]), nil
}

// Term derives the term of an exact operator the field answers, for one
// value: an index term for a field declared with indexes, the query value's
// JSON for a field that names an EQL type. The generated method for the
// operator converts it to its query type. The engine picks the index that
// answers the operator ([encrypt.Cipher.QueryTerm]).
func (f Field[T]) Term(ctx context.Context, c *encrypt.Cipher, operator string, v T) ([]byte, error) {
	terms, err := f.query(ctx, c, operator, v, 1)
	if err != nil {
		return nil, err
	}
	return terms[0], nil
}

// Range derives the two terms of a range operator the field answers, such
// as between: the low bound's term, then the high bound's.
func (f Field[T]) Range(ctx context.Context, c *encrypt.Cipher, operator string, lo, hi T) ([]byte, []byte, error) {
	terms, err := f.query(ctx, c, operator, []any{lo, hi}, 2)
	if err != nil {
		return nil, nil, err
	}
	return terms[0], terms[1], nil
}

// NullTerm derives an exact operator's term for nil: for eq on a field that
// stores nil as a sealed null, the term every such nil shares, so it finds
// the rows whose value is absent. The engine refuses it for any other field
// or operator: nothing else stores a null's term.
func (f Field[T]) NullTerm(ctx context.Context, c *encrypt.Cipher, operator string) ([]byte, error) {
	terms, err := f.query(ctx, c, operator, nil, 1)
	if err != nil {
		return nil, err
	}
	return terms[0], nil
}

// query derives an exact operator's terms, and refuses an answer of another
// shape than the generated method's: a probabilistic term has a query type
// of its own (Matches). Each operand is converted to the field's kind as a
// written value is ([asKind]), so the query finds what a write stored.
func (f Field[T]) query(ctx context.Context, c *encrypt.Cipher, operator string, input any, parts int) ([][]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if c == nil {
		return nil, fmt.Errorf("%w: gensupport: %s: a query needs a cipher", encrypt.ErrEncoding, f.name)
	}
	pair, isPair := input.([]any)
	values := []any{input}
	if isPair {
		values = pair
	}
	converted := make([]any, len(values))
	for i, v := range values {
		value, err := asKind(f.kind(), v)
		if err != nil {
			return nil, fmt.Errorf("gensupport: %s: %w", f.name, err)
		}
		converted[i] = value
	}
	operand := converted[0]
	if isPair {
		operand = converted
	}
	term, err := c.QueryTerm(ctx, f.plan, f.name, operator, operand)
	if err != nil {
		return nil, err
	}
	if term.Fidelity != record.Exact || len(term.Terms) != parts {
		return nil, fmt.Errorf("gensupport: %s: %s came back as a %s term of %d parts, not an exact one of %d", f.name, operator, term.Fidelity, len(term.Terms), parts)
	}
	return term.Terms, nil
}

// Matches derives the matches query for one value of a field declared with
// a match index: the term, and what Verify and TargetLimit need. A function,
// not a method, because only a string field answers matches. A nil cipher
// is refused by [encrypt.NewMatchQuery], with [encrypt.ErrEncoding].
func Matches[T ~string](ctx context.Context, f Field[T], c *encrypt.Cipher, v T) (encrypt.MatchQuery[T], error) {
	if f.err != nil {
		return encrypt.MatchQuery[T]{}, f.err
	}
	return encrypt.NewMatchQuery(ctx, c, f.plan, f.name, v)
}

// EQLMatches derives the matches query for one value of a field that names
// an EQL type with a match index: the type's query value Q, and what Verify
// and TargetLimit need.
func EQLMatches[Q ~[]byte, T ~string](ctx context.Context, f Field[T], c *encrypt.Cipher, v T) (encrypt.EQLMatchQuery[Q, T], error) {
	if f.err != nil {
		return encrypt.EQLMatchQuery[Q, T]{}, f.err
	}
	return encrypt.NewEQLMatchQuery[Q](ctx, c, f.plan, f.name, v)
}
