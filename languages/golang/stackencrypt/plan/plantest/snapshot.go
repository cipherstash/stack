package plantest

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

// header opens every snapshot. One sentence per line: the file is read in
// diffs, where a rewrapped paragraph would read as a change.
const header = `# Written by plantest.Golden: what the policy stores each field it decides as.
# Regenerate it with go test -update; do not edit it by hand.
# A column's context is bound into every ciphertext and query term written under it, so once a row is written it must never change.
`

// snapshot is what a message's policy stores each field it decides as:
// the persistent half of a plan, which a rename the policy pins leaves
// alone.
type snapshot struct {
	table     string
	columns   []column // encrypted fields, by column
	plaintext []plain  // fields decided Plaintext, by field
}

// column is one encrypted field, named by its record key.
type column struct {
	name    string
	context string
	// kind is how the context is bound: kindEQL when it is the column
	// identity, "<table>/<column>", so the table and a column rename move
	// it; kindCustom when the target supplies it whatever the column, so
	// several columns may share it.
	kind  string
	terms []string
	facts []fact
	// from is the field it is decided from now; nil when read from a file.
	from *decided
}

// plain is one field decided Plaintext, named by its schema name.
type plain struct {
	field string
	facts []fact
	from  *decided
}

// decided is a field of the message as the policy sees it now.
type decided struct {
	fact     plan.Fact
	decision plan.Decision
}

// The kinds of target a column is stored as.
const (
	kindEQL    = "EQL"
	kindCustom = "Custom"
)

// targetKind is kindEQL when t binds the column identity as its context,
// as [plan.EQL] does, and kindCustom when it binds anything else, as
// [plan.Custom] does. It asks the target rather than its type, so a typed
// EQL target counts as EQL. It asks twice, with two identities: a Custom
// context is fixed, so it may equal one of them but never both. A target
// that refuses either identity is an error, not a kind.
func targetKind(t plan.Target) (string, error) {
	for _, probe := range []plan.Identifier{{Table: "plantest", Column: "a"}, {Table: "plantest", Column: "b"}} {
		got, err := t.Context(probe)
		if err != nil {
			return "", fmt.Errorf("plantest: target %v refuses the identity %s: %w", t, probe, err)
		}
		label, err := probe.Label()
		if err != nil {
			return "", fmt.Errorf("plantest: the probe identity %s: %w", probe, err)
		}
		if !got.Equal(label.Context()) {
			return kindCustom, nil
		}
	}
	return kindEQL, nil
}

// contextText is the text a snapshot stores for a column's context, the
// same text the policy spells it with. An EQL column's context is its
// identity's label, the pair (table, column identity), stored as
// "<table>/<identity>"; a Custom column's is the one text part
// [plan.Custom] was given, stored as written. The two are told apart by
// the column's target line, not by the text. The text is checked against
// the context the plan actually binds, so the file cannot name a context
// the plan does not use.
func contextText(table string, kind string, d plan.Decision, fp stackencrypt.FieldPlan) (string, error) {
	var text string
	var want stackencrypt.Context
	switch kind {
	case kindEQL:
		identity := d.Identity()
		if identity == "" {
			identity = fp.Name
		}
		label, err := plan.Identifier{Table: table, Column: identity}.Label()
		if err != nil {
			return "", fmt.Errorf("plantest: column %q: %w", fp.Name, err)
		}
		text, want = label.String(), label.Context()
	default:
		// A Custom context has no accessor: plan.Custom renders its
		// argument quoted, as Custom("<context>", ...), so read it back.
		target, _ := d.Target()
		spelled, ok := strings.CutPrefix(fmt.Sprint(target), "Custom(")
		var err error
		if ok {
			if text, err = strconv.QuotedPrefix(spelled); err == nil {
				text, err = strconv.Unquote(text)
			}
		}
		if !ok || err != nil {
			return "", fmt.Errorf("plantest: column %q: cannot spell the context of target %v; a target that does not bind its column identity must be plan.Custom", fp.Name, target)
		}
		var l stackencrypt.Label
		if l, err = stackencrypt.ParseLabel(text); err != nil {
			return "", fmt.Errorf("plantest: column %q: %w", fp.Name, err)
		}
		want = l.Context()
	}
	if !want.Equal(fp.Context) {
		return "", fmt.Errorf("plantest: column %q: the plan binds a context other than %q", fp.Name, text)
	}
	return text, nil
}

// contextOf is the context a snapshot's column names, rebuilt from its
// text and target kind: what [contextText] wrote.
func contextOf(c column) (stackencrypt.Context, error) {
	label, err := stackencrypt.ParseLabel(c.context)
	if err != nil {
		return stackencrypt.Context{}, err
	}
	return label.Context(), nil
}

// fact is one annotation value.
type fact struct{ key, value string }

// take builds m's plan from src, as plan.PlanFor does at startup, and
// snapshots it. It returns the facts as well, for the hints a comparison
// builds.
func take(src plan.Source, m plan.Message) (snapshot, []plan.Fact, error) {
	if src == nil {
		return snapshot{}, nil, errors.New("plantest: Golden needs a Source")
	}
	p, err := plan.PlanFor(src, m)
	if err != nil && !errors.Is(err, plan.ErrNothingEncrypted) {
		return snapshot{}, nil, err
	}
	facts, err := src.Facts(m.Msg())
	if err != nil {
		return snapshot{}, nil, err
	}
	planned := map[string]stackencrypt.FieldPlan{}
	for _, fp := range p.Fields() {
		planned[fp.Field] = fp
	}
	s := snapshot{table: string(m.Table())}
	seen := map[string]bool{}
	for _, f := range facts {
		d, ok := m.Decide(f)
		if !ok {
			// Unclassified and unnamed: PlanFor has already refused a
			// classified field no rule decides.
			continue
		}
		if seen[f.Field] {
			return snapshot{}, nil, fmt.Errorf("plantest: the source gives field %q twice", f.Field)
		}
		seen[f.Field] = true
		from := &decided{fact: f, decision: d}
		if _, encrypted := d.Target(); !encrypted {
			s.plaintext = append(s.plaintext, plain{field: f.Field, facts: factsOf(f), from: from})
			continue
		}
		target, _ := d.Target()
		fp, ok := planned[goField(f)]
		if !ok {
			return snapshot{}, nil, fmt.Errorf("plantest: %s is decided %v but is not in the plan", f, d)
		}
		terms := make([]string, len(fp.Terms))
		for i, k := range fp.Terms {
			terms[i] = k.String()
		}
		kind, err := targetKind(target)
		if err != nil {
			return snapshot{}, nil, err
		}
		context, err := contextText(s.table, kind, d, fp)
		if err != nil {
			return snapshot{}, nil, err
		}
		s.columns = append(s.columns, column{name: fp.Name, context: context, kind: kind, terms: terms, facts: factsOf(f), from: from})
	}
	s.sort()
	return s, facts, nil
}

// goField is the Go field a fact binds to, as the plan package spells it.
func goField(f plan.Fact) string {
	if f.GoField != "" {
		return f.GoField
	}
	return f.Field
}

// factsOf is a field's annotations as sorted, distinct (key, value) pairs:
// their order in the schema means nothing to a policy.
func factsOf(f plan.Fact) []fact {
	var out []fact
	for _, a := range f.Annotations {
		for _, v := range a.Values {
			out = append(out, fact{a.Key, v})
		}
	}
	sortFacts(out)
	return slices.Compact(out)
}

func sortFacts(fs []fact) {
	slices.SortFunc(fs, func(a, b fact) int {
		if c := strings.Compare(a.key, b.key); c != 0 {
			return c
		}
		return strings.Compare(a.value, b.value)
	})
}

func (s *snapshot) sort() {
	slices.SortFunc(s.columns, func(a, b column) int { return strings.Compare(a.name, b.name) })
	slices.SortFunc(s.plaintext, func(a, b plain) int { return strings.Compare(a.field, b.field) })
}

// render spells the snapshot. parse reads it back.
func (s snapshot) render() []byte {
	var b bytes.Buffer
	b.WriteString(header)
	fmt.Fprintf(&b, "\ntable %s\n", token(s.table))
	for _, c := range s.columns {
		fmt.Fprintf(&b, "\ncolumn %s\n", token(c.name))
		fmt.Fprintf(&b, "  context %s\n", token(c.context))
		fmt.Fprintf(&b, "  target %s\n", c.kind)
		fmt.Fprintf(&b, "  terms %s\n", termList(c.terms))
		writeFacts(&b, c.facts)
	}
	for _, p := range s.plaintext {
		fmt.Fprintf(&b, "\nplaintext %s\n", token(p.field))
		writeFacts(&b, p.facts)
	}
	return b.Bytes()
}

// termList spells a column's terms, "none" for none: an unindexed column
// is a decision too, and says nothing about the value but its ciphertext.
// Each term goes through token like every other value, so a term name
// with a space could not split into two. Term names are TermKind.String()
// values, none of them "none".
func termList(terms []string) string {
	if len(terms) == 0 {
		return "none"
	}
	parts := make([]string, len(terms))
	for i, t := range terms {
		parts[i] = token(t)
	}
	return strings.Join(parts, " ")
}

func writeFacts(b *bytes.Buffer, facts []fact) {
	for _, f := range facts {
		fmt.Fprintf(b, "  fact %s %s\n", token(f.key), token(f.value))
	}
}

// token spells a value: bare when it is a plain identifier, a Go string
// literal otherwise, so a space, a quote or a newline in a name or a
// context cannot change how the line reads.
func token(s string) string {
	if s == "" {
		return strconv.Quote(s)
	}
	for i := 0; i < len(s); i++ {
		if !bare(s[i]) {
			return strconv.Quote(s)
		}
	}
	return s
}

// bare reports whether c may appear in an unquoted value.
func bare(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '_' || c == '.' || c == '/' || c == '-' || c == ':' || c == '@' || c == '+'
}

// parse reads a snapshot render wrote. It is strict about structure and
// lenient about nothing else: any byte difference fails the comparison
// anyway, and parse only lets the failure say what changed.
func parse(data []byte) (snapshot, error) {
	var s snapshot
	var table bool
	// The entry the indented lines below belong to: a column (>= 0), a
	// plaintext field (plainAt >= 0), or neither.
	colAt, plainAt := -1, -1
	for n, line := range strings.Split(string(normalize(data)), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indented := strings.HasPrefix(line, "  ")
		toks, err := tokens(strings.TrimSpace(line))
		if err != nil {
			return snapshot{}, fmt.Errorf("line %d: %w", n+1, err)
		}
		switch {
		case !indented && toks[0] == "table" && len(toks) == 2 && !table:
			s.table, table = toks[1], true
		case !indented && toks[0] == "column" && len(toks) == 2:
			s.columns = append(s.columns, column{name: toks[1]})
			colAt, plainAt = len(s.columns)-1, -1
		case !indented && toks[0] == "plaintext" && len(toks) == 2:
			s.plaintext = append(s.plaintext, plain{field: toks[1]})
			colAt, plainAt = -1, len(s.plaintext)-1
		case indented && toks[0] == "context" && len(toks) == 2 && colAt >= 0:
			s.columns[colAt].context = toks[1]
		case indented && toks[0] == "target" && len(toks) == 2 && colAt >= 0 && (toks[1] == kindEQL || toks[1] == kindCustom):
			s.columns[colAt].kind = toks[1]
		case indented && toks[0] == "terms" && len(toks) >= 2 && colAt >= 0:
			if len(toks) == 2 && toks[1] == "none" {
				s.columns[colAt].terms = nil
			} else {
				s.columns[colAt].terms = toks[1:]
			}
		case indented && toks[0] == "fact" && len(toks) == 3 && colAt >= 0:
			s.columns[colAt].facts = append(s.columns[colAt].facts, fact{toks[1], toks[2]})
		case indented && toks[0] == "fact" && len(toks) == 3 && plainAt >= 0:
			s.plaintext[plainAt].facts = append(s.plaintext[plainAt].facts, fact{toks[1], toks[2]})
		default:
			return snapshot{}, fmt.Errorf("line %d: unexpected %q", n+1, line)
		}
	}
	if !table {
		return snapshot{}, errors.New("no table line")
	}
	// compare reads a column's context and target kind: one without them
	// would read as a Custom-free, contextless column, and a table rename
	// as harmless.
	for _, c := range s.columns {
		if c.kind == "" || c.context == "" {
			return snapshot{}, fmt.Errorf("column %q has no context or target line", c.name)
		}
	}
	for i := range s.columns {
		sortFacts(s.columns[i].facts)
	}
	for i := range s.plaintext {
		sortFacts(s.plaintext[i].facts)
	}
	s.sort()
	return s, nil
}

// tokens splits a line into its values, unquoting the quoted ones.
func tokens(line string) ([]string, error) {
	var out []string
	for line != "" {
		if line[0] == '"' {
			q, err := strconv.QuotedPrefix(line)
			if err != nil {
				return nil, fmt.Errorf("bad quoted value in %q", line)
			}
			v, err := strconv.Unquote(q)
			if err != nil {
				return nil, fmt.Errorf("bad quoted value in %q", line)
			}
			out = append(out, v)
			line = line[len(q):]
		} else {
			end := strings.IndexByte(line, ' ')
			if end < 0 {
				end = len(line)
			}
			out = append(out, line[:end])
			line = line[end:]
		}
		line = strings.TrimLeft(line, " ")
	}
	if len(out) == 0 {
		return nil, errors.New("empty line")
	}
	return out, nil
}
