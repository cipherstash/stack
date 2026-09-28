package plan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
)

// Identifier is a field's column identity: the table its message is
// stored in and the column it encrypts into. For an EQL target it is the
// field's encryption context, so it is fixed at first write and must never
// change — which is why the table is given, never derived from a message
// name, and why a rule can pin the column ([Column]) across renames.
type Identifier struct {
	Table  string
	Column string
}

// String is the context an EQL target binds: "<table>/<column>", the
// shape the Rust derive gives a `#[stash(struct = T, context = "<table>")]`
// field.
func (id Identifier) String() string { return id.Table + "/" + id.Column }

// Target is what an encrypted field is stored as: the index terms derived
// beside its ciphertext, and the context it binds. The context is the
// AAD, the ZeroKMS data-key binding and the terms' PRF context at once.
type Target interface {
	// Terms lists the index terms to derive, in order.
	Terms() []stackencrypt.TermKind
	// Context returns the field's context given its column identity. An
	// EQL target returns id.String(); a custom target returns its own.
	Context(id Identifier) string
}

// EQL is an EQL column target: the field binds its column identity
// ([Identifier.String]) as its context and derives the given terms. Typed
// EQL targets (a text-with-equality column, say) are this with the terms
// filled in, and implement [Target] the same way.
func EQL(terms ...stackencrypt.TermKind) Target {
	return eqlTarget{terms: slices.Clone(terms)}
}

type eqlTarget struct{ terms []stackencrypt.TermKind }

func (t eqlTarget) Terms() []stackencrypt.TermKind { return slices.Clone(t.terms) }
func (t eqlTarget) Context(id Identifier) string   { return id.String() }
func (t eqlTarget) String() string                 { return "EQL(" + termList(t.terms) + ")" }

// Custom is a non-EQL target: the field binds context, whatever its
// column, and derives the given terms. The context need not be
// table/column shaped; it is the policy's to choose and, like any context,
// must never change once data is written under it.
func Custom(context string, terms ...stackencrypt.TermKind) Target {
	return customTarget{context: context, terms: slices.Clone(terms)}
}

type customTarget struct {
	context string
	terms   []stackencrypt.TermKind
}

func (t customTarget) Terms() []stackencrypt.TermKind { return slices.Clone(t.terms) }
func (t customTarget) Context(Identifier) string      { return t.context }
func (t customTarget) String() string {
	return fmt.Sprintf("Custom(%q%s)", t.context, prefixed(termList(t.terms)))
}

func termList(terms []stackencrypt.TermKind) string {
	names := make([]string, len(terms))
	for i, k := range terms {
		names[i] = k.String()
	}
	return strings.Join(names, ", ")
}

func prefixed(s string) string {
	if s == "" {
		return ""
	}
	return ", " + s
}

type verdict uint8

const (
	encrypt verdict = iota + 1
	plaintext
	fail
)

// Decision is what a policy decides for one field: encrypt it into a
// target, leave it plaintext, or refuse it. Build one with [Encrypt],
// [Plaintext] or [Fail].
type Decision struct {
	verdict verdict
	target  Target
	reason  string
	column  string
}

// Encrypt decides that the field is encrypted into target.
func Encrypt(target Target) Decision { return Decision{verdict: encrypt, target: target} }

// Plaintext decides that the field is stored as it is: not part of the
// plan, never sent to the guest.
func Plaintext() Decision { return Decision{verdict: plaintext} }

// Fail decides that the field must not be planned at all: building the
// plan fails, naming the field and reason.
func Fail(reason string) Decision { return Decision{verdict: fail, reason: reason} }

// Target returns the decision's target, and whether it encrypts at all.
func (d Decision) Target() (Target, bool) { return d.target, d.verdict == encrypt }

// Column returns the column the decision pins, or "" for the field's own.
func (d Decision) Column() string { return d.column }

// String spells the decision for tests and errors.
func (d Decision) String() string {
	var s string
	switch d.verdict {
	case encrypt:
		s = fmt.Sprintf("Encrypt(%v)", d.target)
	case plaintext:
		s = "Plaintext()"
	case fail:
		s = fmt.Sprintf("Fail(%q)", d.reason)
	default:
		return "Decision{}"
	}
	if d.column != "" {
		s += fmt.Sprintf(" Column(%q)", d.column)
	}
	return s
}

// Policy maps a field's facts to a decision, or reports no match (false).
// It is a pure function — no I/O, no client — so a policy is tested by
// calling it on hand-built facts. Policies compose with [FirstOf] and
// [Policy.OrElse]; [When] is the leaf.
type Policy func(Fact) (Decision, bool)

// Decide runs the policy on one field. A nil policy matches nothing.
func (p Policy) Decide(f Fact) (Decision, bool) {
	if p == nil {
		return Decision{}, false
	}
	return p(f)
}

// OrElse is p, falling back to q for the fields p does not match: the
// per-message refinement over a base policy.
func (p Policy) OrElse(q Policy) Policy { return FirstOf(p, q) }

// FirstOf is the first of policies that matches a field, in order. Nil
// policies are skipped.
func FirstOf(policies ...Policy) Policy {
	policies = slices.Clone(policies)
	return func(f Fact) (Decision, bool) {
		for _, p := range policies {
			if d, ok := p.Decide(f); ok {
				return d, true
			}
		}
		return Decision{}, false
	}
}

// RuleOption adjusts the decision a [When] rule makes.
type RuleOption func(*Decision)

// Column pins the column an encrypted field is stored under: its record
// name and, for an EQL target, the column half of its context. The pin is
// the column's identity, which may differ from the field's name after a
// field rename, and from the column's current name after a database
// rename: stored payloads keep the identity they were written under. Only
// meaningful with [Encrypt]; building a plan refuses it elsewhere.
func Column(name string) RuleOption {
	return func(d *Decision) { d.column = name }
}

// When decides d for the fields m matches, and matches nothing else.
func When(m Matcher, d Decision, opts ...RuleOption) Policy {
	if m == nil {
		panic("plan.When: nil matcher")
	}
	for _, opt := range opts {
		opt(&d)
	}
	return func(f Fact) (Decision, bool) {
		if !m(f) {
			return Decision{}, false
		}
		return d, true
	}
}

// Matcher is a predicate over a field's facts.
type Matcher func(Fact) bool

// Field matches the field whose schema name ([Fact.Field]) is name.
func Field(name string) Matcher {
	return func(f Fact) bool { return f.Field == name }
}

// Kind matches fields of the given kind, in the source's spelling.
func Kind(kind string) Matcher {
	return func(f Fact) bool { return f.Kind == kind }
}

// Any matches when at least one of ms does.
func Any(ms ...Matcher) Matcher {
	return func(f Fact) bool {
		return slices.ContainsFunc(ms, func(m Matcher) bool { return m(f) })
	}
}

// All matches when every one of ms does.
func All(ms ...Matcher) Matcher {
	return func(f Fact) bool {
		for _, m := range ms {
			if !m(f) {
				return false
			}
		}
		return true
	}
}

// Not matches when m does not.
func Not(m Matcher) Matcher {
	return func(f Fact) bool { return !m(f) }
}

// Key is an annotation key, the handle rules match annotations through. A
// protobuf fact source hands out a Key per extension; for struct tags it
// is the tag's key:
//
//	var category = plan.Key("fides.data_categories")
type Key string

// Present matches fields with any value under the key.
func (k Key) Present() Matcher {
	return func(f Fact) bool { return len(f.Values(string(k))) > 0 }
}

// Is matches fields with value among their values under the key.
func (k Key) Is(value string) Matcher {
	return func(f Fact) bool { return slices.Contains(f.Values(string(k)), value) }
}

// Under matches fields with a value under the key at or below prefix in a
// dot-separated taxonomy (Fideslang's): "user.contact" matches
// "user.contact" and "user.contact.email", not "user.contactless".
func (k Key) Under(prefix string) Matcher {
	return func(f Fact) bool {
		return slices.ContainsFunc(f.Values(string(k)), func(v string) bool {
			return v == prefix || strings.HasPrefix(v, prefix+".")
		})
	}
}
