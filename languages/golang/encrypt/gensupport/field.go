package gensupport

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Field is one sealed field's entry in a generated Fields value: it encrypts
// one value of the field, for an update of one column, and derives the
// terms the field declares, for a query. T is the field's Go type.
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
	f.plan = &record.Plan{Context: plan.Context, Fields: []record.Field{*rf}}
	return f
}

// Encrypt seals one value of the field: its ciphertext and every term it
// declares, in one request.
func (f Field[T]) Encrypt(ctx context.Context, c *encrypt.Cipher, v T) (Output, error) {
	if f.err != nil {
		return Output{}, f.err
	}
	if c == nil {
		return Output{}, fmt.Errorf("gensupport: %s: Encrypt needs a cipher", f.name)
	}
	sealed, err := c.Seal(ctx, f.plan, []record.Source{{f.name: v}})
	if err != nil {
		return Output{}, err
	}
	if len(sealed) != 1 {
		return Output{}, fmt.Errorf("gensupport: %s: one value came back as %d", f.name, len(sealed))
	}
	return outputOf(sealed[0][f.name]), nil
}

// Query derives the EQL query value for one value of an encrypt_into field.
// No EQL type is available in this build of the engine, so it fails.
func (f Field[T]) Query(context.Context, *encrypt.Cipher, T) (Output, error) {
	if f.err != nil {
		return Output{}, f.err
	}
	return Output{}, fmt.Errorf("gensupport: %s: EQL types are not available yet", f.name)
}

// Equality derives the field's equality term for one value.
func (f Field[T]) Equality(ctx context.Context, c *encrypt.Cipher, v T) (encrypt.EqualityTerm, error) {
	return f.term(ctx, c, record.Equality, v)
}

// Match derives the field's match term for one value.
func (f Field[T]) Match(ctx context.Context, c *encrypt.Cipher, v T) (encrypt.MatchTerm, error) {
	return f.term(ctx, c, record.Match, v)
}

// Ore derives the field's ORE term for one value.
func (f Field[T]) Ore(ctx context.Context, c *encrypt.Cipher, v T) (encrypt.OreTerm, error) {
	return f.term(ctx, c, record.Ore, v)
}

// Ope derives the field's OPE term for one value.
func (f Field[T]) Ope(ctx context.Context, c *encrypt.Cipher, v T) (encrypt.OpeTerm, error) {
	return f.term(ctx, c, record.Ope, v)
}

// JSON derives the field's json index term. The engine does not derive it
// yet, so it fails.
func (f Field[T]) JSON(context.Context, *encrypt.Cipher, T) (encrypt.JSONTerm, error) {
	if f.err != nil {
		return nil, f.err
	}
	return nil, fmt.Errorf("gensupport: %s: the engine does not derive the json index yet", f.name)
}

func (f Field[T]) term(ctx context.Context, c *encrypt.Cipher, output record.Output, v T) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if c == nil {
		return nil, fmt.Errorf("gensupport: %s: a term needs a cipher", f.name)
	}
	return c.Derive(ctx, f.plan, f.name, output, v)
}
