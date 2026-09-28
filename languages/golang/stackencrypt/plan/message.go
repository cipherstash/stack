package plan

import (
	"errors"
	"fmt"
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
	// a pinned column on a field that is not encrypted, an empty context or
	// column identity.
	ErrInvalid = errors.New("invalid decision")
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
//	        plan.When(plan.Field("MedicareNo"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
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
	for _, f := range facts {
		fp, planned, err := m.field(f)
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
	p, err := stackencrypt.NewPlan(fields...)
	if err != nil {
		return stackencrypt.Plan{}, fmt.Errorf("plan: %s: %w", messageName(m, facts), err)
	}
	return p, nil
}

// field decides one field: its plan field, and whether it is planned.
func (m Message) field(f Fact) (stackencrypt.FieldPlan, bool, error) {
	d, ok := m.policy.Decide(f)
	if !ok {
		if len(f.Annotations) == 0 {
			return stackencrypt.FieldPlan{}, false, nil
		}
		return stackencrypt.FieldPlan{}, false, ErrUnmatched
	}
	switch d.verdict {
	case encrypt:
	case plaintext:
		if d.column != "" {
			return stackencrypt.FieldPlan{}, false, fmt.Errorf("%w: Column(%q) pinned on a Plaintext field", ErrInvalid, d.column)
		}
		return stackencrypt.FieldPlan{}, false, nil
	case fail:
		return stackencrypt.FieldPlan{}, false, fmt.Errorf("%w: %s", ErrRefused, d.reason)
	default:
		return stackencrypt.FieldPlan{}, false, fmt.Errorf("%w: the zero Decision", ErrInvalid)
	}
	if d.target == nil {
		return stackencrypt.FieldPlan{}, false, fmt.Errorf("%w: Encrypt with no target", ErrInvalid)
	}
	column := f.Field
	if d.column != "" {
		column = d.column
	}
	if column == "" || strings.Contains(column, "/") {
		return stackencrypt.FieldPlan{}, false, fmt.Errorf("%w: column %q must be non-empty and contain no '/'", ErrInvalid, column)
	}
	context := d.target.Context(Identifier{Table: string(m.table), Column: column})
	if context == "" {
		return stackencrypt.FieldPlan{}, false, fmt.Errorf("%w: target %v gives an empty context", ErrInvalid, d.target)
	}
	return stackencrypt.FieldPlan{
		Field:   f.goField(),
		Name:    column,
		Context: context,
		Terms:   d.target.Terms(),
	}, true, nil
}

func messageName(m Message, facts []Fact) string {
	if len(facts) > 0 && facts[0].Message != "" {
		return facts[0].Message
	}
	return fmt.Sprintf("%T", m.msg)
}

// PlanFor reads m's facts from src and builds its plan; see
// [Message.Build].
func PlanFor(src Source, m Message) (stackencrypt.Plan, error) {
	if src == nil {
		return stackencrypt.Plan{}, errors.New("plan: PlanFor needs a Source")
	}
	facts, err := src.Facts(m.msg)
	if err != nil {
		return stackencrypt.Plan{}, err
	}
	return m.Build(facts)
}

// MustPlanFor is [PlanFor] for startup: it panics when the policy does not
// decide every classified field, so a policy gap stops the process before
// it writes anything.
func MustPlanFor(src Source, m Message) stackencrypt.Plan {
	p, err := PlanFor(src, m)
	if err != nil {
		panic(err)
	}
	return p
}
