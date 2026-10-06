package encrypt

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Checker asks the embedded engine about declarations, with no credentials,
// no keyset and no network: what stashgen uses to refuse a declaration the
// engine would refuse, and to learn which EQL types the engine produces. It
// holds a guest instance that was never given a client key, so every other
// operation on it is [ErrState].
type Checker struct {
	c *Client
}

// NewChecker instantiates the embedded guest for the generator's questions.
func NewChecker(ctx context.Context) (*Checker, error) {
	wasm, err := embeddedGuest()
	if err != nil {
		return nil, err
	}
	t := &transport{rt: refusingTransport{}, token: noToken{}}
	inst, err := newInstance(ctx, wasm, t, guest.BestEffort)
	if err != nil {
		return nil, err
	}
	return &Checker{c: newClient(inst, t)}, nil
}

// Close releases the guest.
func (k *Checker) Close() error { return k.c.Close() }

// Check refuses a plan the engine would refuse: an index its field's type
// does not admit, a context that is not a label, two fields under one
// identity. The error is [ErrEncoding]; which rule failed is the engine's to
// know, so a caller that wants the field named checks one field at a time.
func (k *Checker) Check(ctx context.Context, plan *record.Plan) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encoded, err := vcffi.Marshal(plan.Wire())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	_, err = k.c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.planCheck, buf(encoded))
	})
	return err
}

// Targets lists the EQL types this build of the engine produces: none until
// the EQL target dispatch lands.
func (k *Checker) Targets(ctx context.Context) ([]record.Target, error) {
	out, err := k.c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.targets)
	})
	if err != nil {
		return nil, err
	}
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	obj, ok := decoded.(vcvalue.Object)
	if !ok || len(obj) != 1 || obj[0].Key != "targets" {
		return nil, fmt.Errorf("%w: se_targets returned %T", ErrInternal, decoded)
	}
	items, ok := obj[0].Value.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: se_targets returned %T for the list", ErrInternal, obj[0].Value)
	}
	targets := make([]record.Target, 0, len(items))
	for _, item := range items {
		entry, ok := item.(vcvalue.Object)
		if !ok {
			return nil, fmt.Errorf("%w: a target came back as %T", ErrInternal, item)
		}
		var t record.Target
		for _, f := range entry {
			switch f.Key {
			case "name":
				t.Name, _ = f.Value.(string)
			case "kind":
				kind, _ := f.Value.(string)
				t.Kind = record.Kind(kind)
			case "query":
				t.Query, _ = f.Value.(string)
			case "terms":
				terms, _ := f.Value.([]any)
				for _, term := range terms {
					s, _ := term.(string)
					t.Terms = append(t.Terms, record.Output(s))
				}
			}
		}
		if t.Name == "" {
			return nil, fmt.Errorf("%w: a target has no name", ErrInternal)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// refusingTransport fails every request: the checker makes none.
type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("encrypt: the checker makes no request")
}

// noToken has no token: the checker needs none.
type noToken struct{}

func (noToken) Token(context.Context) (string, error) {
	return "", errors.New("encrypt: the checker has no credentials")
}
