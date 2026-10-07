// Package policy decides how a type that cannot carry stash tags is
// encrypted, from what its schema says about each field.
//
// Tags are the way to declare a type that you write. A policy is for a type
// that a schema generates, such as a protobuf message whose field options hold
// the field's data categories. A [Source] gives the facts about each field; a
// rule has a [Matcher] and a [Decision]; the first rule that matches a field
// decides it. stashgen.Generate runs the rules and writes the same generated
// file that it writes from tags. Only the generate program runs a policy.
//
// Every field of the message needs a decision. A field that no rule decides
// stops the generator with the field's name and its annotations. A policy has
// an [Otherwise] rule only when its author writes one.
package policy

import (
	"fmt"
	"strings"
)

// Fact is what a source knows about one field: its name, its Go name, its
// kind and its annotations. A policy reads facts and never learns where they
// came from.
type Fact struct {
	// Message is the full name of the message, for errors.
	Message string
	// Name is the field's name in the schema, such as the proto field name.
	// It is the column name unless a rule gives another with [Name].
	Name string
	// GoName is the field of the Go struct the schema generated.
	GoName string
	// Kind is the field's kind in the schema's own words, such as "string" or
	// "int64". Rules may match on it.
	Kind string
	// Annotations are what the schema says about the field, such as its
	// data categories.
	Annotations []Annotation
}

// Annotation is one annotation on a field: a key and its values. For a
// protobuf field option the key is the option's full name.
type Annotation struct {
	Key    string
	Values []string
}

// Values returns every value under key, in order.
func (f Fact) Values(key string) []string {
	var out []string
	for _, a := range f.Annotations {
		if a.Key == key {
			out = append(out, a.Values...)
		}
	}
	return out
}

// String spells the field and its annotations, for the error that names a
// field no rule decides.
func (f Fact) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s.%s (%s", f.Message, f.Name, f.Kind)
	for _, a := range f.Annotations {
		fmt.Fprintf(&b, "; %s = %s", a.Key, strings.Join(a.Values, ", "))
	}
	b.WriteString(")")
	return b.String()
}

// Source gives the facts about each field of a message.
type Source interface {
	// Facts returns one fact for each field of the message, in declared
	// order. The message is the value given to [ForMessage].
	Facts(message any) ([]Fact, error)
}

// SourceFunc is a Source made from a function.
type SourceFunc func(message any) ([]Fact, error)

// Facts calls the function.
func (s SourceFunc) Facts(message any) ([]Fact, error) { return s(message) }

// Matcher selects the fields a rule applies to.
type Matcher interface {
	Match(Fact) bool
}

// MatcherFunc is a Matcher made from a function.
type MatcherFunc func(Fact) bool

// Match calls the function.
func (m MatcherFunc) Match(f Fact) bool { return m(f) }

// Field matches the field with this schema name.
func Field(name string) Matcher {
	return MatcherFunc(func(f Fact) bool { return f.Name == name })
}

// Key is an annotation key, such as the full name of a protobuf field option.
type Key string

// Under matches a field with a value under key that is prefix, or starts
// with prefix and a dot: Key("c").Under("user") matches "user" and
// "user.contact.email", and not "username".
func (k Key) Under(prefix string) Matcher {
	return MatcherFunc(func(f Fact) bool {
		for _, v := range f.Values(string(k)) {
			if v == prefix || strings.HasPrefix(v, prefix+".") {
				return true
			}
		}
		return false
	})
}

// Is matches a field with a value under key equal to value.
func (k Key) Is(value string) Matcher {
	return MatcherFunc(func(f Fact) bool {
		for _, v := range f.Values(string(k)) {
			if v == value {
				return true
			}
		}
		return false
	})
}

// Decision is what a rule decides for a field: one of the tag verbs, or a
// refusal. A decision spells itself in the tag grammar, so the generator
// reads a policy's decision through the same parser as a tag.
type Decision struct {
	verb    string
	indexes []IndexSpec
	eqlType string
	fail    bool
	reason  string
}

// Encrypt seals the field with no index.
func Encrypt() Decision { return Decision{verb: "encrypt"} }

// EncryptIndex seals the field and derives each index beside it.
func EncryptIndex(indexes ...IndexSpec) Decision {
	return Decision{verb: "encrypt,index", indexes: indexes}
}

// Index derives the indexes alone, with no ciphertext.
func Index(indexes ...IndexSpec) Decision { return Decision{verb: "index", indexes: indexes} }

// EncryptInto seals the field into one EQL value of this type.
func EncryptInto(eqlType string) Decision { return Decision{verb: "encrypt_into", eqlType: eqlType} }

// Passthrough stores the field as it is.
func Passthrough() Decision { return Decision{verb: "passthrough"} }

// Omit leaves the field out.
func Omit() Decision { return Decision{verb: "-"} }

// Fail refuses the field: the generator stops with the reason.
func Fail(reason string) Decision { return Decision{fail: true, reason: reason} }

// IndexName is one of the tag words for an index: equality, match, ore, ope
// or json.
type IndexName string

// IndexOption is one option of an index, as the tag writes it in parentheses.
type IndexOption struct {
	Key   string
	Value string
}

// IndexSpec is one index with its options, as a rule names it: the engine's
// own word for the data form of an index.
type IndexSpec struct {
	Name    IndexName
	Options []IndexOption
}

// The indexes that take no options.
var (
	Equality = IndexSpec{Name: "equality"}
	Ore      = IndexSpec{Name: "ore"}
	Ope      = IndexSpec{Name: "ope"}
)

// Match is the match index, with its options.
func Match(options ...IndexOption) IndexSpec { return IndexSpec{Name: "match", Options: options} }

// JSON is the json index, with its options.
func JSON(options ...IndexOption) IndexSpec { return IndexSpec{Name: "json", Options: options} }

// String spells the index as a tag does: match or match(k=3).
func (i IndexSpec) String() string {
	if len(i.Options) == 0 {
		return string(i.Name)
	}
	opts := make([]string, len(i.Options))
	for n, o := range i.Options {
		opts[n] = o.Key
		if o.Value != "" {
			opts[n] += "=" + o.Value
		}
	}
	return string(i.Name) + "(" + strings.Join(opts, ",") + ")"
}

// Outcome is a decision applied to one field: the decision, and the name
// and identity a rule's options set.
type Outcome struct {
	Decision Decision
	// Name is the column name, or "" for the field's schema name.
	Name string
	// Identity is the field's part of its context, or "" for the column
	// name. A field whose column is renamed keeps its identity, so data
	// written before the change still decrypts.
	Identity string
}

// Tag spells the outcome for a field in the tag grammar: what the field's
// stash tag would say. ok is false for a refusal, which [Outcome.Reason]
// explains, and for the zero Outcome.
func (o Outcome) Tag(name string) (tag string, ok bool) {
	d := o.Decision
	if d.fail || d.verb == "" {
		return "", false
	}
	if d.verb == "-" {
		return "-", true
	}
	if o.Name != "" {
		name = o.Name
	}
	switch d.verb {
	case "encrypt_into":
		return name + ",encrypt_into=" + d.eqlType, true
	case "encrypt,index", "index":
		names := make([]string, len(d.indexes))
		for i, idx := range d.indexes {
			names[i] = idx.String()
		}
		return name + "," + d.verb + "=" + strings.Join(names, ";"), true
	}
	return name + "," + d.verb, true
}

// Reason is the reason of a Fail decision, or "".
func (o Outcome) Reason() string {
	if !o.Decision.fail {
		return ""
	}
	return o.Decision.reason
}

// Option modifies a rule's outcome.
type Option func(*Outcome)

// Name sets the field's column name.
func Name(column string) Option { return func(o *Outcome) { o.Name = column } }

// Identity keeps the field's context when its column gets a new name.
func Identity(identity string) Option { return func(o *Outcome) { o.Identity = identity } }

// Rule decides a field, or reports that it does not match.
type Rule interface {
	Decide(Fact) (Outcome, bool)
}

// When is a rule: the fields the matcher selects get the decision.
func When(m Matcher, d Decision, options ...Option) Rule {
	return rule{m: m, outcome: outcome(d, options)}
}

// Otherwise decides every field that no earlier rule matched.
func Otherwise(d Decision, options ...Option) Rule {
	return rule{m: MatcherFunc(func(Fact) bool { return true }), outcome: outcome(d, options)}
}

func outcome(d Decision, options []Option) Outcome {
	o := Outcome{Decision: d}
	for _, opt := range options {
		opt(&o)
	}
	return o
}

type rule struct {
	m       Matcher
	outcome Outcome
}

func (r rule) Decide(f Fact) (Outcome, bool) {
	if !r.m.Match(f) {
		return Outcome{}, false
	}
	return r.outcome, true
}

// Rules are rules tried in order; the first that matches decides.
type Rules []Rule

// FirstOf returns the rules, tried in order.
func FirstOf(rules ...Rule) Rules { return Rules(rules) }

// Decide tries each rule in order.
func (r Rules) Decide(f Fact) (Outcome, bool) {
	for _, rule := range r {
		if rule == nil {
			continue
		}
		if o, ok := rule.Decide(f); ok {
			return o, true
		}
	}
	return Outcome{}, false
}

// OrElse returns the rules, then other for the fields they do not match.
func (r Rules) OrElse(other Rule) Rules {
	return append(append(Rules{}, r...), other)
}

// Context is the context of every field of a message, as the `context=` tag
// gives it for a struct.
type Context string

// Message is one message with its context and its rules, as [ForMessage]
// builds it and stashgen.Generate reads it.
type Message struct {
	message any
	context Context
	rules   Rule
}

// ForMessage binds a message to its context and the rules that decide its
// fields. The message is a value of the generated Go type, such as
// &pb.Individual{}; the source reads its schema and the generator its type.
func ForMessage(message any, context Context, rules Rule) Message {
	return Message{message: message, context: context, rules: rules}
}

// Message returns the message value given to ForMessage.
func (m Message) Message() any { return m.message }

// Context returns the message's context.
func (m Message) Context() string { return string(m.context) }

// Decide runs the rules on one field.
func (m Message) Decide(f Fact) (Outcome, bool) {
	if m.rules == nil {
		return Outcome{}, false
	}
	return m.rules.Decide(f)
}
