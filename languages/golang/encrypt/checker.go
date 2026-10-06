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
// identity. The error is [ErrEncoding]. A refusal from the engine is a
// [*Diagnostic] that names the field with [Diagnostic.Field] and the rule
// with [Diagnostic.Reason].
func (k *Checker) Check(ctx context.Context, plan *record.Plan) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return k.engineCheck(ctx, plan)
}

// engineCheck asks se_plan_check alone, with no host rule first: the half
// of Check that reaches the engine.
func (k *Checker) engineCheck(ctx context.Context, plan *record.Plan) error {
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
	return parseTargets(decoded)
}

// parseTargets reads se_targets's decoded value: {"targets": [entry, ...]},
// each entry an object with exactly the keys record.Target documents. The
// shape is a contract between eql-bindings' serialiser and this reader, so
// an unknown key, a missing name, or a value of the wrong type is
// ErrInternal: a decoder that kept a zero value would let stashgen decide an
// encrypt_into on a type with no kind or no indexes.
func parseTargets(decoded any) ([]record.Target, error) {
	obj, ok := decoded.(vcvalue.Object)
	if !ok || len(obj) != 1 || obj[0].Key != "targets" {
		return nil, fmt.Errorf("%w: se_targets returned %T, not {\"targets\": [...]}", ErrInternal, decoded)
	}
	items, ok := obj[0].Value.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: se_targets returned %T for the list", ErrInternal, obj[0].Value)
	}
	targets := make([]record.Target, 0, len(items))
	for i, item := range items {
		entry, ok := item.(vcvalue.Object)
		if !ok {
			return nil, fmt.Errorf("%w: target %d came back as %T", ErrInternal, i, item)
		}
		t, err := parseTarget(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: target %d: %v", ErrInternal, i, err)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func parseTarget(entry vcvalue.Object) (record.Target, error) {
	var t record.Target
	seen := map[string]bool{}
	for _, f := range entry {
		if seen[f.Key] {
			return t, fmt.Errorf("key %q twice", f.Key)
		}
		seen[f.Key] = true
		var err error
		switch f.Key {
		case "name":
			t.Name, err = targetString(f)
		case "family":
			t.Family, err = targetString(f)
		case "suffix":
			t.Suffix, err = targetString(f)
		case "plaintext":
			var kind string
			kind, err = targetOptionalString(f)
			t.Plaintext = record.Kind(kind)
			if err == nil && !t.Plaintext.Known() {
				err = fmt.Errorf("plaintext %q is not a kind", kind)
			}
		case "sql_domain":
			t.SQLDomain, err = targetString(f)
		case "indexes":
			list, ok := f.Value.([]any)
			if !ok {
				return t, fmt.Errorf("indexes is %T, not a list", f.Value)
			}
			for _, item := range list {
				s, ok := item.(string)
				if !ok {
					return t, fmt.Errorf("an index is %T, not a string", item)
				}
				switch o := record.Output(s); o {
				// "json" is the SteVec document index, which no plan output
				// carries.
				case record.Equality, record.Match, record.Ore, record.Ope, "json":
					t.Indexes = append(t.Indexes, o)
				default:
					return t, fmt.Errorf("unknown index %q", s)
				}
			}
		case "query":
			t.Query, err = targetOptionalString(f)
		case "query_sql_domain":
			t.QuerySQLDomain, err = targetOptionalString(f)
		case "producible":
			b, ok := f.Value.(bool)
			if !ok {
				return t, fmt.Errorf("producible is %T, not a bool", f.Value)
			}
			t.Producible = b
		case "reason":
			t.Reason, err = targetOptionalString(f)
		default:
			return t, fmt.Errorf("unknown key %q", f.Key)
		}
		if err != nil {
			return t, err
		}
	}
	if t.Name == "" {
		return t, errors.New("no name")
	}
	for _, key := range []string{"indexes", "producible"} {
		if !seen[key] {
			return t, fmt.Errorf("no %s", key)
		}
	}
	return t, nil
}

func targetString(f vcvalue.Field) (string, error) {
	s, ok := f.Value.(string)
	if !ok {
		return "", fmt.Errorf("%s is %T, not a string", f.Key, f.Value)
	}
	return s, nil
}

func targetOptionalString(f vcvalue.Field) (string, error) {
	if f.Value == nil {
		return "", nil
	}
	return targetString(f)
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
