package plan

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

// Identifier is a field's column identity: the table its message is
// stored in and the column its data was first written to. For an EQL
// target it is the field's encryption context, so it is fixed at first
// write and must never change — which is why the table is given, never
// derived from a message name, and why a rule can pin the column half
// ([Identity]) apart from the column the value is stored in ([Column])
// once the database column is renamed.
type Identifier struct {
	Table  string
	Column string
}

// String joins the table and the column with '/', for messages. The context
// an EQL target binds, and the descriptor ZeroKMS logs for it, is
// [Identifier.Label], which refuses a name this joining would misrender.
func (id Identifier) String() string { return id.Table + "/" + id.Column }

// Label is the identifier as the two-segment [encrypt.Label] an EQL
// target binds: the shape the Rust derive gives a
// `#[stash(struct = T, context = "<table>")]` field, and what EQL's own
// Identifier describes. It is refused when either half is not plain —
// contains '/', '(' or ')', a control character, or begins with "b64:", a
// digit or '-' — since such a name would not render as itself.
func (id Identifier) Label() (encrypt.Label, error) {
	return encrypt.NewLabel(id.Table, id.Column)
}

// Target is what an encrypted field is stored as: the index terms derived
// beside its ciphertext, and the context it binds. The context is the
// AAD, the ZeroKMS data-key binding and the terms' PRF context at once.
type Target interface {
	// Terms lists the index terms to derive, in order.
	Terms() []encrypt.TermKind
	// Context returns the field's context given its column identity. An
	// EQL target binds id.Label(); a custom target returns its own.
	Context(id Identifier) (encrypt.Context, error)
}

// EQL is an EQL column target: the field binds its column identity
// ([Identifier.Label]) as its context and derives the given terms. Typed
// EQL targets (a text-with-equality column, say) are this with the terms
// filled in, and implement [Target] the same way.
func EQL(terms ...encrypt.TermKind) Target {
	return eqlTarget{terms: slices.Clone(terms)}
}

type eqlTarget struct{ terms []encrypt.TermKind }

func (t eqlTarget) Terms() []encrypt.TermKind { return slices.Clone(t.terms) }
func (t eqlTarget) Context(id Identifier) (encrypt.Context, error) {
	l, err := id.Label()
	if err != nil {
		// The label error names a segment index; the caller gave a table and
		// a column identity, so say which of those it was.
		half, name := "table", id.Table
		var le *encrypt.LabelError
		if errors.As(err, &le) && le.Index == 1 {
			half, name = "column identity", id.Column
		}
		return encrypt.Context{}, fmt.Errorf("%s %q cannot name a context: %w", half, name, err)
	}
	return l.Context(), nil
}
func (t eqlTarget) String() string { return "EQL(" + termList(t.terms) + ")" }

// Custom is a non-EQL target: the field binds context, whatever its
// column, and derives the given terms. The context is the policy's to
// choose and, like any context, must never change once data is written
// under it. It is a label of at least two plain segments, written as
// [encrypt.ParseLabel] reads it ("notes/v1": the segments notes and
// v1, rendered as written in the ZeroKMS log), since that is the one shape
// of context a planned field binds; the message's table plays no part in
// it. A table and a column are an [EQL] target.
func Custom(context string, terms ...encrypt.TermKind) Target {
	return customTarget{context: context, terms: slices.Clone(terms)}
}

type customTarget struct {
	context string
	terms   []encrypt.TermKind
}

func (t customTarget) Terms() []encrypt.TermKind { return slices.Clone(t.terms) }
func (t customTarget) Context(Identifier) (encrypt.Context, error) {
	if t.context == "" {
		return encrypt.Context{}, errors.New("an empty string is an empty context")
	}
	l, err := encrypt.ParseLabel(t.context)
	if err != nil {
		return encrypt.Context{}, fmt.Errorf("context %q is not a label: %w", t.context, err)
	}
	return l.Context(), nil
}
func (t customTarget) String() string {
	return fmt.Sprintf("Custom(%q%s)", t.context, prefixed(termList(t.terms)))
}

func termList(terms []encrypt.TermKind) string {
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
	sealed verdict = iota + 1
	plaintext
	fail
)

// Decision is what a policy decides for one field: encrypt it into a
// target, leave it plaintext, or refuse it. Build one with [Encrypt],
// [Plaintext] or [Fail].
type Decision struct {
	verdict  verdict
	target   Target
	reason   string
	column   string
	identity string
}

// Encrypt decides that the field is encrypted into target.
func Encrypt(target Target) Decision { return Decision{verdict: sealed, target: target} }

// Plaintext decides that the field is stored as it is: not part of the
// plan, never sent to the guest.
func Plaintext() Decision { return Decision{verdict: plaintext} }

// Fail decides that the field must not be planned at all: building the
// plan fails, naming the field and reason.
func Fail(reason string) Decision { return Decision{verdict: fail, reason: reason} }

// Target returns the decision's target, and whether it encrypts at all.
func (d Decision) Target() (Target, bool) { return d.target, d.verdict == sealed }

// Column returns the column the decision stores the field in, or "" for
// the field's own name.
func (d Decision) Column() string { return d.column }

// Identity returns the column half of the identity the decision pins, or
// "" for the effective column's (see [Identity]).
func (d Decision) Identity() string { return d.identity }

// String spells the decision for tests and errors.
func (d Decision) String() string {
	var s string
	switch d.verdict {
	case sealed:
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
	if d.identity != "" {
		s += fmt.Sprintf(" Identity(%q)", d.identity)
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

// Column names the column an encrypted field is stored in: its record
// key ([encrypt.FieldPlan.Name]). It defaults to the field's schema
// name, so a rule needs it only when the two differ — after the field is
// renamed in the schema, say. For an EQL target, the column also sets the
// field's identity unless [Identity] pins another: on a field never
// renamed in the database, Column alone is enough. Only meaningful with
// [Encrypt]; building a plan refuses it elsewhere. An empty name is a
// programming error and panics: a pin that is not there would silently
// store the field under its own name instead.
func Column(name string) RuleOption {
	if name == "" {
		panic("plan.Column: empty column name")
	}
	return func(d *Decision) { d.column = name }
}

// Identity pins the column half of an EQL field's identity
// ([Identifier]), and so its context "<table>/<column>": the AAD bound to
// every stored ciphertext, its ZeroKMS data-key binding and its terms' PRF
// context. It defaults to the effective [Column], so a field whose
// database column has never been renamed needs no Identity.
//
// Once data is written, a field's identity must never change: rows
// written under the old one would no longer decrypt, and their terms would
// no longer match queries. A database rename (ALTER TABLE ... RENAME
// COLUMN) is therefore spelled as the new column and the old identity:
//
//	plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(encrypt.Equality)),
//	    plan.Column("medicare_no"), plan.Identity("medicare_number"))
//
// Only meaningful with an EQL [Encrypt]: a [Custom] target's context is
// its own, and building a plan refuses Identity there and on [Plaintext].
// An empty name is a programming error and panics, as for [Column].
func Identity(name string) RuleOption {
	if name == "" {
		panic("plan.Identity: empty column name")
	}
	return func(d *Decision) { d.identity = name }
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

// Any matches when at least one of ms does. A nil matcher, or none at
// all, is a programming error and panics here, as it does in [When].
func Any(ms ...Matcher) Matcher {
	ms = matchers("plan.Any", ms)
	return func(f Fact) bool {
		return slices.ContainsFunc(ms, func(m Matcher) bool { return m(f) })
	}
}

// All matches when every one of ms does. A nil matcher, or none at all,
// is a programming error and panics here, as it does in [When]: with no
// matchers All would match every field, so a rule built from a slice that
// came back empty would decide every field below it. A policy that needs
// a catch-all writes a final rule whose matcher says so.
func All(ms ...Matcher) Matcher {
	ms = matchers("plan.All", ms)
	return func(f Fact) bool {
		for _, m := range ms {
			if !m(f) {
				return false
			}
		}
		return true
	}
}

// Not matches when m does not. A nil matcher is a programming error and
// panics here, as it does in [When].
func Not(m Matcher) Matcher {
	if m == nil {
		panic("plan.Not: nil matcher")
	}
	return func(f Fact) bool { return !m(f) }
}

// matchers is a combinator's own copy of its matchers, none of them nil:
// a later write to the caller's slice must not change the matcher, and a
// nil found now names the combinator instead of crashing a build.
func matchers(combinator string, ms []Matcher) []Matcher {
	if len(ms) == 0 {
		panic(combinator + ": no matchers; All() would match every field and Any() none")
	}
	for i, m := range ms {
		if m == nil {
			panic(fmt.Sprintf("%s: nil matcher at index %d", combinator, i))
		}
	}
	return slices.Clone(ms)
}

// Key is an annotation key, the handle rules match annotations through. A
// protobuf fact source hands out a Key per extension; for struct tags it
// is the tag's key:
//
//	var category = plan.Key("fides.data_categories")
type Key string

// Present matches fields with any value under the key.
func (k Key) Present() Matcher {
	return func(f Fact) bool { return f.hasValue(string(k), func(string) bool { return true }) }
}

// Is matches fields with value among their values under the key.
func (k Key) Is(value string) Matcher {
	return func(f Fact) bool { return f.hasValue(string(k), func(v string) bool { return v == value }) }
}

// Under matches fields with a value under the key at or below prefix in a
// dot-separated taxonomy (Fideslang's): "user.contact" matches
// "user.contact" and "user.contact.email", not "user.contactless". The
// prefix is one or more non-empty dot-separated segments; anything else
// ("", "user.", ".user", "a..b") could match nothing while reading as a
// catch-all, so it is a programming error and panics.
func (k Key) Under(prefix string) Matcher {
	if prefix == "" || slices.Contains(strings.Split(prefix, "."), "") {
		panic(fmt.Sprintf("plan.Key(%q).Under(%q): a prefix is one or more non-empty dot-separated segments", string(k), prefix))
	}
	below := prefix + "."
	return func(f Fact) bool {
		return f.hasValue(string(k), func(v string) bool {
			return v == prefix || strings.HasPrefix(v, below)
		})
	}
}
