package plan

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
)

var (
	// ErrUnmatched is a field that carries annotations no rule of the
	// policy decides. There is no built-in default: a catch-all, even
	// Plaintext, must be written in the policy.
	ErrUnmatched = errors.New("no rule decides the field")
	// ErrRefused is a field the policy decided to [Fail].
	ErrRefused = errors.New("the policy refuses the field")
	// ErrInvalid is a decision that cannot become a plan field: no target,
	// a pinned column or identity on a field that is not encrypted, an
	// identity on a Custom target, an empty context, a '/' in a column
	// identity, or two EQL fields sharing one identity.
	ErrInvalid = errors.New("invalid decision")
	// ErrNothingEncrypted is a message the policy encrypts no field of:
	// every classified field decided Plaintext, or none classified. Such a
	// message has no plan to build, and its records are stored without
	// one — a [stackencrypt.Plan] always seals at least one field.
	ErrNothingEncrypted = errors.New("the policy encrypts no field of the message")
)

// Table names the table a message's records are stored in: the first half
// of every EQL field's column identity. It is required, and never derived
// from the message's name, because it is part of every context and a
// guess (a pluralisation) would be permanent.
type Table string

// Message is a policy for one message type: the message, its table, and
// the rules its fields are decided by. A Message is a value; build it once
// (a package-level var) and build its plan at startup with [MustPlanFor].
type Message struct {
	msg    any
	table  Table
	policy Policy
}

// ForMessage scopes policy to msg, stored in table. msg is what the
// [Source] reads facts from: a struct value or pointer for [StructTags], a
// proto.Message for a protobuf source. Refine a shared base per message
// with OrElse:
//
//	var Individuals = plan.ForMessage(&Individual{}, plan.Table("individuals"),
//	    plan.FirstOf(
//	        plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
//	            plan.Column("medicare_number")),
//	    ).OrElse(Base),
//	)
func ForMessage(msg any, table Table, policy Policy) Message {
	return Message{msg: msg, table: table, policy: policy}
}

// Msg returns the message the policy is for.
func (m Message) Msg() any { return m.msg }

// Table returns the message's table.
func (m Message) Table() Table { return m.table }

// Decide runs the message's policy on one field.
func (m Message) Decide(f Fact) (Decision, bool) { return m.policy.Decide(f) }

// Build decides every field of facts and returns the plan: one field per
// Encrypt decision, in fact order. A field no rule matches is plaintext
// when it has no annotations (not the policy's concern) and ErrUnmatched
// when it has any; a Fail decision is ErrRefused. Every failing field is
// reported, not only the first, each naming the field and its facts.
//
// Pure: no I/O, no client. Build is what [PlanFor] runs after reading the
// facts, and what a generator or a golden test runs on facts it holds.
func (m Message) Build(facts []Fact) (stackencrypt.Plan, error) {
	if m.table == "" {
		return stackencrypt.Plan{}, fmt.Errorf("plan: %s: a message needs a Table", messageName(m, facts))
	}
	if strings.Contains(string(m.table), "/") {
		return stackencrypt.Plan{}, fmt.Errorf("plan: %s: table %q contains '/', which would make its column identities ambiguous", messageName(m, facts), m.table)
	}
	var fields []stackencrypt.FieldPlan
	var errs []error
	// An EQL identity is one column's context: two fields sharing one would
	// bind each other's ciphertexts and terms. NewPlan refuses a shared
	// record key, but with Identity the identity can be shared without one.
	identities := map[string]Fact{}
	for _, f := range facts {
		fp, id, planned, err := m.field(f)
		if err == nil && id != "" {
			if prev, dup := identities[id]; dup {
				err = fmt.Errorf("%w: identity %q is already field %s's", ErrInvalid, id, prev.Field)
			} else {
				identities[id] = f
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("plan: %s: %w", f, err))
			continue
		}
		if planned {
			fields = append(fields, fp)
		}
	}
	if len(errs) > 0 {
		return stackencrypt.Plan{}, errors.Join(errs...)
	}
	if len(fields) == 0 {
		return stackencrypt.Plan{}, fmt.Errorf("plan: %s: %w; a message with nothing to encrypt needs no plan", messageName(m, facts), ErrNothingEncrypted)
	}
	p, err := stackencrypt.NewPlan(fields...)
	if err != nil {
		return stackencrypt.Plan{}, fmt.Errorf("plan: %s: %w", messageName(m, facts), err)
	}
	return p, nil
}

// field decides one field: its plan field, its EQL identity ("" for a
// Custom target), and whether it is planned.
func (m Message) field(f Fact) (stackencrypt.FieldPlan, string, bool, error) {
	none := func(err error) (stackencrypt.FieldPlan, string, bool, error) {
		return stackencrypt.FieldPlan{}, "", false, err
	}
	d, ok := m.policy.Decide(f)
	if !ok {
		if len(f.Annotations) == 0 {
			return none(nil)
		}
		return none(ErrUnmatched)
	}
	switch d.verdict {
	case encrypt:
	case plaintext:
		if d.column != "" {
			return none(fmt.Errorf("%w: Column(%q) pinned on a Plaintext field", ErrInvalid, d.column))
		}
		if d.identity != "" {
			return none(fmt.Errorf("%w: Identity(%q) pinned on a Plaintext field", ErrInvalid, d.identity))
		}
		return none(nil)
	case fail:
		return none(fmt.Errorf("%w: %s", ErrRefused, d.reason))
	default:
		return none(fmt.Errorf("%w: the zero Decision", ErrInvalid))
	}
	if d.target == nil {
		return none(fmt.Errorf("%w: Encrypt with no target", ErrInvalid))
	}
	column := f.Field
	if d.column != "" {
		column = d.column
	}
	if column == "" {
		return none(fmt.Errorf("%w: the field has no name to store it under", ErrInvalid))
	}
	_, custom := d.target.(customTarget)
	identity := column
	if custom {
		// A Custom target's context is its own: there is no identity to
		// pin, and a pin would read as if it took effect.
		if d.identity != "" {
			return none(fmt.Errorf("%w: Identity(%q) on %v, whose context is fixed", ErrInvalid, d.identity, d.target))
		}
		identity = ""
	} else if d.identity != "" {
		identity = d.identity
	}
	// A '/' in an EQL column would make an identity-shaped context
	// ambiguous ("a/b" under "t" reads as "a" under "t/b" would), and the
	// column is the identity until the day it is renamed. A Custom
	// target's column is only the record key.
	if !custom {
		for _, name := range []string{column, identity} {
			if strings.Contains(name, "/") {
				return none(fmt.Errorf("%w: column %q contains '/', which would make its identity ambiguous", ErrInvalid, name))
			}
		}
	}
	context := d.target.Context(Identifier{Table: string(m.table), Column: identity})
	if context == "" {
		return none(fmt.Errorf("%w: target %v gives an empty context", ErrInvalid, d.target))
	}
	return stackencrypt.FieldPlan{
		Field:   f.goField(),
		Name:    column,
		Context: context,
		Terms:   d.target.Terms(),
	}, identity, true, nil
}

func messageName(m Message, facts []Fact) string {
	if len(facts) > 0 && facts[0].Message != "" {
		return facts[0].Message
	}
	return fmt.Sprintf("%T", m.msg)
}

// PlanFor reads m's facts from src, builds its plan (see [Message.Build])
// and, when m's message is a struct or a pointer to one, checks the plan
// binds to it: every planned field is an exported, direct field of the
// type. A fact whose GoField the type does not have — a typo in a source,
// a generated field renamed — is then an error here, not at the first
// record call.
func PlanFor(src Source, m Message) (stackencrypt.Plan, error) {
	if src == nil {
		return stackencrypt.Plan{}, errors.New("plan: PlanFor needs a Source")
	}
	facts, err := src.Facts(m.msg)
	if err != nil {
		return stackencrypt.Plan{}, err
	}
	p, err := m.Build(facts)
	if err != nil {
		return stackencrypt.Plan{}, err
	}
	if t := structType(m.msg); t != nil {
		if err := p.Validate(t); err != nil {
			return stackencrypt.Plan{}, fmt.Errorf("plan: %s: %w", messageName(m, facts), err)
		}
	}
	return p, nil
}

// structType is msg's struct type, through one pointer, or nil when msg is
// not a struct: nothing to bind a plan to.
func structType(msg any) reflect.Type {
	t := reflect.TypeOf(msg)
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	return t
}

// MustPlanFor is [PlanFor] for startup: it panics when the policy does not
// decide every classified field, or the plan does not bind to the message,
// so a policy gap stops the process before it writes anything.
func MustPlanFor(src Source, m Message) stackencrypt.Plan {
	p, err := PlanFor(src, m)
	if err != nil {
		panic(err)
	}
	return p
}
