package plantest

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

// changes is what differs between a snapshot and the policy now, sorted
// by what each costs.
type changes struct {
	// contexts lose data: a context no field writes any more.
	contexts []string
	// migrations need rows rewritten: a target that changed under a
	// context that did not.
	migrations []string
	// other changes cost nothing already written: a new field, a changed
	// fact, a field the policy no longer decides.
	other []string
}

// explain says what changed between the snapshot want and the policy now.
func explain(want []byte, cur snapshot, facts []plan.Fact, m plan.Message) string {
	old, err := parse(want)
	if err != nil {
		return fmt.Sprintf("The snapshot does not parse (%v), so its changes cannot be sorted; the diff below shows them.\n\n", err)
	}
	return compare(old, cur, facts, m).String()
}

func (c changes) String() string {
	var b strings.Builder
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		b.WriteString(title)
		b.WriteString("\n")
		for _, it := range items {
			fmt.Fprintf(&b, "  - %s\n", it)
		}
		b.WriteString("\n")
	}
	section("CONTEXT CHANGES. These lose data: a context is bound into every ciphertext and query term written under it, so rows already written under the old one no longer decrypt, and their terms no longer match queries. Keep the old context by pinning the field's rule with plan.Column (and plan.Identity after a database column rename).", c.contexts)
	section("TARGET CHANGES. These need a migration: rows already written keep what they were written with until they are rewritten.", c.migrations)
	section("OTHER CHANGES.", c.other)
	if b.Len() == 0 {
		return "Nothing the policy stores changed, but the snapshot's text did: an edit by hand, or a newer plantest.\n\n"
	}
	return b.String()
}

// compare sorts the differences between the snapshot old and the policy
// now (cur, built from facts by m).
func compare(old, cur snapshot, facts []plan.Fact, m plan.Message) changes {
	var c changes
	if old.table != cur.table {
		// Only an EQL column's context is under the table; a Custom one is
		// the target's own, and a plaintext field has none.
		if slices.ContainsFunc(old.columns, func(o column) bool { return o.kind == kindEQL }) {
			c.contexts = append(c.contexts, fmt.Sprintf("the message's table is %s, was %s. The table is the first half of every EQL column's context; restore plan.Table(%q).",
				token(cur.table), token(old.table), old.table))
		} else {
			c.other = append(c.other, fmt.Sprintf("the message's table is %s, was %s. No context moves with it: the message has no EQL column, whose context is the only one under the table.",
				token(cur.table), token(old.table)))
		}
	}

	oldCols, curCols := byName(old.columns), byName(cur.columns)
	oldPlain, curPlain := byField(old.plaintext), byField(cur.plaintext)
	oldContexts, curContexts := map[string]bool{}, map[string][]string{}
	for _, o := range old.columns {
		oldContexts[contextKey(o)] = true
	}
	for _, n := range cur.columns {
		curContexts[contextKey(n)] = append(curContexts[contextKey(n)], token(n.name))
	}
	// The entries now that an old one accounts for, and the old plaintext
	// fields an entry now accounts for.
	seenCol, seenPlain, seenOldPlain := map[string]bool{}, map[string]bool{}, map[string]bool{}

	for _, o := range old.columns {
		if n, ok := curCols[o.name]; ok {
			seenCol[n.name] = true
			if !sameContext(o, n) {
				c.contexts = append(c.contexts, fmt.Sprintf("column %s: its context is %s, was %s. %s",
					token(o.name), n.context, o.context, pinAdvice(m, facts, n.from, o, old.table)))
			}
			c.stored(o, n)
			continue
		}
		// A database column rename: a new column under the same context.
		// Only an EQL context is evidence of one, being the column's own
		// identity; Custom columns may share a context with no relation
		// between them.
		if n, ok := only(cur.columns, func(n column) bool {
			_, before := oldCols[n.name]
			return !before && !seenCol[n.name] && sameContext(n, o) && o.kind == kindEQL && n.kind == kindEQL
		}); ok {
			seenCol[n.name] = true
			c.migrations = append(c.migrations, fmt.Sprintf("column %s is now stored in column %s, under the same context: the database column is renamed with it (ALTER TABLE ... RENAME COLUMN).",
				token(o.name), token(n.name)))
			c.stored(o, n)
			continue
		}
		// Decided Plaintext now: under the column's name, or the only new
		// plaintext field with its facts.
		if p, ok := only(cur.plaintext, func(p plain) bool {
			_, before := oldPlain[p.field]
			return !before && !seenPlain[p.field] && (p.field == o.name || len(o.facts) > 0 && slices.Equal(p.facts, o.facts))
		}); ok {
			seenPlain[p.field] = true
			c.migrations = append(c.migrations, fmt.Sprintf("column %s is now field %s, decided Plaintext. Rows already written hold ciphertexts under %s, which a migration must decrypt before the field is read as plaintext.",
				token(o.name), token(p.field), o.context))
			continue
		}
		// The context is still written, by a column sharing a Custom
		// context: nothing already written stops decrypting, but nothing
		// reads this column.
		if writers := curContexts[contextKey(o)]; len(writers) > 0 {
			still := "column " + writers[0] + " still writes it"
			if len(writers) > 1 {
				still = "columns " + strings.Join(writers, ", ") + " still write it"
			}
			c.other = append(c.other, fmt.Sprintf("column %s is no longer written. Its context %s is not lost, since %s, but no field reads column %s now: if its field was renamed, pin the renamed field's rule with plan.Column(%q).",
				token(o.name), o.context, still, token(o.name), o.name))
			continue
		}
		// The context is lost. The only new column with the same facts,
		// under a context new to the snapshot, may be the same field
		// renamed. Matching facts are no proof: an unrelated new field can
		// carry the same ones, and pinning it would store two fields in one
		// column. So the guess states both readings, and the column is
		// still listed as new.
		msg := fmt.Sprintf("column %s: no field writes its context %s any more.", token(o.name), o.context)
		if n, ok := only(cur.columns, func(n column) bool {
			_, before := oldCols[n.name]
			return !before && !seenCol[n.name] && !oldContexts[contextKey(n)] && len(o.facts) > 0 && slices.Equal(n.facts, o.facts)
		}); ok {
			seenCol[n.name] = true
			msg += fmt.Sprintf(" Field %s now writes column %s under %s with the same facts, so it may be the same field renamed: %s"+
				" If %s is instead a new field and %s was removed, do not pin it: that would store two fields in column %s under one context.",
				fieldName(n.from), token(n.name), n.context, pinAdvice(m, facts, n.from, o, old.table),
				token(n.name), token(o.name), token(o.name))
			c.other = append(c.other, fmt.Sprintf("new column %s, under %s, with terms [%s]. It is also named above as a possible rename of column %s.",
				token(n.name), n.context, termList(n.terms), token(o.name)))
			c.stored(o, n)
		} else {
			msg += fmt.Sprintf(" If its field was renamed, pin the renamed field's rule with plan.Column(%q); if it was removed, rows written under it can no longer be read through this policy.", o.name)
		}
		c.contexts = append(c.contexts, msg)
	}

	for _, n := range cur.columns {
		if seenCol[n.name] {
			continue
		}
		if n.from != nil {
			if p, ok := oldPlain[n.from.fact.Field]; ok {
				if _, still := curPlain[p.field]; !still {
					seenOldPlain[p.field] = true
					c.migrations = append(c.migrations, fmt.Sprintf("field %s, decided Plaintext before, is now encrypted into column %s under %s. Rows already written hold its plaintext, which a migration must encrypt.",
						token(p.field), token(n.name), n.context))
					continue
				}
			}
		}
		c.other = append(c.other, fmt.Sprintf("new column %s, under %s, with terms [%s].", token(n.name), n.context, termList(n.terms)))
	}

	for _, o := range old.plaintext {
		if n, ok := curPlain[o.field]; ok {
			if !slices.Equal(o.facts, n.facts) {
				c.other = append(c.other, fmt.Sprintf("plaintext field %s: its facts are [%s], were [%s].", token(o.field), factList(n.facts), factList(o.facts)))
			}
			continue
		}
		if !seenOldPlain[o.field] {
			c.other = append(c.other, fmt.Sprintf("plaintext field %s is no longer decided by the policy (renamed, removed, or no longer classified).", token(o.field)))
		}
	}
	for _, n := range cur.plaintext {
		if _, before := oldPlain[n.field]; !before && !seenPlain[n.field] {
			c.other = append(c.other, fmt.Sprintf("new plaintext field %s.", token(n.field)))
		}
	}
	return c
}

// stored compares what one column stores, the context aside.
func (c *changes) stored(o, n column) {
	if !slices.Equal(o.terms, n.terms) {
		c.migrations = append(c.migrations, fmt.Sprintf("column %s: its terms are [%s], were [%s]. Rows already written carry the terms they were written with until they are re-encrypted, so a query on a new term misses them.",
			token(n.name), termList(n.terms), termList(o.terms)))
	}
	if o.kind != n.kind {
		// A changed context is reported on its own, under CONTEXT CHANGES.
		where := ", under the same context"
		if !sameContext(o, n) {
			where = ""
		}
		c.other = append(c.other, fmt.Sprintf("column %s: its target is %s, was %s%s.", token(n.name), n.kind, o.kind, where))
	}
	if !slices.Equal(o.facts, n.facts) {
		c.other = append(c.other, fmt.Sprintf("column %s: its facts are [%s], were [%s].", token(n.name), factList(n.facts), factList(o.facts)))
	}
}

// contextKey names a column's context exactly: its segments. An EQL
// context and a Custom one are both labels, so the two kinds share a
// context when their segments match; the kind is how the context was
// chosen, not part of it.
func contextKey(c column) string { return c.context }

// sameContext reports whether a and b bind the same context.
func sameContext(a, b column) bool { return contextKey(a) == contextKey(b) }

// pinAdvice says how to store the field from in the old column under the
// old context again, each answer checked by building the plan with it: the
// old table, when the table moved, with a pin if it needs one; a pin; or
// why no pin can.
func pinAdvice(m plan.Message, facts []plan.Fact, from *decided, old column, oldTable string) string {
	if from == nil {
		return ""
	}
	if oldTable != string(m.Table()) {
		if pin, ok := pin(m, plan.Table(oldTable), facts, from, old); ok {
			if pin == "" {
				return fmt.Sprintf("Restoring plan.Table(%q) brings it back.", oldTable)
			}
			return fmt.Sprintf("Restoring plan.Table(%q) and pinning the rule that decides field %s with %s brings it back.", oldTable, fieldName(from), pin)
		}
	}
	if pin, ok := pin(m, m.Table(), facts, from, old); ok {
		return fmt.Sprintf("Pinning the rule that decides field %s with %s keeps it.", fieldName(from), pin)
	}
	return fmt.Sprintf("No plan.Column or plan.Identity pin on the rule that decides field %s brings it back: the context comes from the target itself (a plan.Custom context, or a change of target), so restore that.", fieldName(from))
}

// pin is the rule options, spelled as Go, that store the field from as
// column under context again in table, checked by building the plan with
// them, and whether any does. With m's own table it tries only pins; with
// another, no pin first ("").
func pin(m plan.Message, table plan.Table, facts []plan.Fact, from *decided, old column) (string, bool) {
	column, context := old.name, old.context
	if column == "" {
		return "", false
	}
	want, err := contextOf(old)
	if err != nil {
		return "", false
	}
	type try struct {
		spelled string
		opts    []plan.RuleOption
	}
	var tries []try
	if table != m.Table() {
		tries = append(tries, try{})
	}
	tries = append(tries, try{fmt.Sprintf("plan.Column(%q)", column), []plan.RuleOption{plan.Column(column)}})
	if segments, err := segmentsOf(context); err == nil && len(segments) == 2 && segments[0] == string(table) {
		id := segments[1]
		tries = append(tries,
			try{fmt.Sprintf("plan.Identity(%q)", id), []plan.RuleOption{plan.Identity(id)}},
			try{fmt.Sprintf("plan.Column(%q), plan.Identity(%q)", column, id), []plan.RuleOption{plan.Column(column), plan.Identity(id)}},
		)
	}
	for _, t := range tries {
		rule := plan.When(plan.Field(from.fact.Field), from.decision, t.opts...)
		p, err := plan.ForMessage(m.Msg(), table, rule.OrElse(m.Decide)).Build(facts)
		if err != nil {
			continue
		}
		for _, fp := range p.Fields() {
			if fp.Field == goField(from.fact) && fp.Name == column && fp.Context.Equal(want) {
				return t.spelled, true
			}
		}
	}
	return "", false
}

// only is the one element of s that keep accepts, if exactly one does.
func only[T any](s []T, keep func(T) bool) (T, bool) {
	var found T
	n := 0
	for _, v := range s {
		if keep(v) {
			found = v
			n++
		}
	}
	if n != 1 {
		var zero T
		return zero, false
	}
	return found, true
}

func byName(cs []column) map[string]column {
	out := make(map[string]column, len(cs))
	for _, c := range cs {
		out[c.name] = c
	}
	return out
}

func byField(ps []plain) map[string]plain {
	out := make(map[string]plain, len(ps))
	for _, p := range ps {
		out[p.field] = p
	}
	return out
}

// fieldName names a field the way a rule matches it, and the Go field it
// binds to when that is spelled differently.
func fieldName(d *decided) string {
	if d == nil {
		return "?"
	}
	name := token(d.fact.Field)
	if g := goField(d.fact); g != d.fact.Field {
		name += " (" + g + ")"
	}
	return name
}

func factList(fs []fact) string {
	if len(fs) == 0 {
		return "none"
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = token(f.key) + "=" + token(f.value)
	}
	return strings.Join(parts, " ")
}

// diff is a unified diff of the snapshot want and the policy now, with
// two lines of context.
func diff(path string, want, got []byte) string {
	es := edits(lines(want), lines(got))
	const context = 2
	keep := make([]bool, len(es))
	for i, e := range es {
		if e.op == ' ' {
			continue
		}
		for j := max(0, i-context); j <= min(len(es)-1, i+context); j++ {
			keep[j] = true
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ the policy now\n", filepath.ToSlash(path))
	for i := 0; i < len(es); {
		if !keep[i] {
			i++
			continue
		}
		end := i
		for end < len(es) && keep[end] {
			end++
		}
		var olds, news int
		for _, e := range es[i:end] {
			if e.op != '+' {
				olds++
			}
			if e.op != '-' {
				news++
			}
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", es[i].a+1, olds, es[i].b+1, news)
		for _, e := range es[i:end] {
			b.WriteByte(e.op)
			b.WriteString(e.line)
			b.WriteByte('\n')
		}
		i = end
	}
	return b.String()
}

// edit is one line of a diff: kept (' '), removed ('-') or added ('+'),
// with the index each side has reached.
type edit struct {
	op   byte
	line string
	a, b int
}

// edits is a shortest edit script from a to b, by longest common
// subsequence. Snapshots are small; past a few million cells it gives up
// on alignment and replaces a with b wholesale.
func edits(a, b []string) []edit {
	var out []edit
	if len(a)*len(b) > 1<<22 {
		for i, l := range a {
			out = append(out, edit{'-', l, i, 0})
		}
		for j, l := range b {
			out = append(out, edit{'+', l, len(a), j})
		}
		return out
	}
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out = append(out, edit{' ', a[i], i, j})
			i++
			j++
		case j == len(b) || i < len(a) && lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, edit{'-', a[i], i, j})
			i++
		default:
			out = append(out, edit{'+', b[j], i, j})
			j++
		}
	}
	return out
}

// lines splits text into its lines, without the final newline's empty
// one.
func lines(text []byte) []string {
	s := strings.TrimSuffix(string(text), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
