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

// Operators lists the operators one field of a plan answers, in the
// engine's order, each with its fidelity, its arity and the index that
// answers it: exactly the operators [Cipher.QueryTerm] derives a term for
// on that field, so stashgen writes one query method for each and holds no
// copy of which index answers which operator. A field the plan does not
// have is [ErrEncoding].
func (k *Checker) Operators(ctx context.Context, plan *record.Plan, field string) ([]record.Operator, error) {
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encoded, err := vcffi.Marshal(plan.Wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	out, err := k.c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.operators, buf(encoded), buf([]byte(field)))
	})
	if err != nil {
		return nil, err
	}
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	operators, err := parseOperators(decoded)
	if err != nil {
		return nil, fmt.Errorf("%w: se_operators: %v", ErrInternal, err)
	}
	return operators, nil
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
		case "operators":
			t.Operators, err = parseOperators(f.Value)
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
	for _, key := range []string{"indexes", "producible", "operators"} {
		if !seen[key] {
			return t, fmt.Errorf("no %s", key)
		}
	}
	return t, nil
}

// parseOperators reads a list of operators, an se_targets entry's or
// se_operators's: a list of objects, each with exactly the keys operator,
// fidelity, arity and index, every value one the engine writes.
func parseOperators(value any) ([]record.Operator, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("operators is %T, not a list", value)
	}
	operators := make([]record.Operator, 0, len(list))
	for i, item := range list {
		entry, ok := item.(vcvalue.Object)
		if !ok {
			return nil, fmt.Errorf("operator %d is %T, not an object", i, item)
		}
		var op record.Operator
		seen := map[string]bool{}
		for _, f := range entry {
			if seen[f.Key] {
				return nil, fmt.Errorf("operator %d: key %q twice", i, f.Key)
			}
			seen[f.Key] = true
			s, err := targetString(f)
			if err != nil {
				return nil, fmt.Errorf("operator %d: %v", i, err)
			}
			switch f.Key {
			case "operator":
				op.Name, err = parseOperatorName(s)
			case "fidelity":
				op.Fidelity, err = parseFidelity(s)
			case "arity":
				switch s {
				case "one":
				case "pair":
					op.Pair = true
				default:
					return nil, fmt.Errorf("operator %d: unknown arity %q", i, s)
				}
			case "index":
				op.Index, err = parseOperatorIndex(s)
			default:
				return nil, fmt.Errorf("operator %d: unknown key %q", i, f.Key)
			}
			if err != nil {
				return nil, fmt.Errorf("operator %d: %v", i, err)
			}
		}
		if len(seen) != 4 || op.Name == "" {
			return nil, fmt.Errorf("operator %d: not every key, or no name", i)
		}
		operators = append(operators, op)
	}
	return operators, nil
}

// parseOperatorName reads an operator's name as the engine writes it: one
// of eq, lt, lte, gt, gte, between and matches, the names the engine's
// OpSpec::parse accepts. The catalog (se_targets) and se_query_term are
// read through this, parseFidelity and parseOperatorIndex, so the two
// readers refuse the same values.
func parseOperatorName(s string) (string, error) {
	switch s {
	case "eq", "lt", "lte", "gt", "gte", "between", "matches":
		return s, nil
	}
	return "", fmt.Errorf("unknown operator %q", s)
}

// parseFidelity reads an operator's fidelity: exact or probabilistic.
func parseFidelity(s string) (record.Fidelity, error) {
	switch f := record.Fidelity(s); f {
	case record.Exact, record.Probabilistic:
		return f, nil
	}
	return "", fmt.Errorf("unknown fidelity %q", s)
}

// parseOperatorIndex reads the index that answers an operator: eq, match,
// ore or ope.
func parseOperatorIndex(s string) (record.Output, error) {
	switch o := record.Output(s); o {
	case record.Equality, record.Match, record.Ore, record.Ope:
		return o, nil
	}
	return "", fmt.Errorf("unknown index %q", s)
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
