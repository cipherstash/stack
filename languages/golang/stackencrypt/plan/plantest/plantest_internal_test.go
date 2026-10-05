package plantest

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/factstest"
	se "github.com/cipherstash/stack/languages/golang/stackencrypt"
	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

var category = plan.Key("fides.data_categories")

var base = plan.FirstOf(
	plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(se.Equality))),
	plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(se.Equality, se.Match))),
	plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
	plan.When(category.Under("system"), plan.Plaintext()),
)

func classified(values ...string) []plan.Annotation {
	return []plan.Annotation{{Key: "fides.data_categories", Values: values}}
}

// proto is a protobuf-shaped source: the facts are given, and a field
// keeps its number through a rename.
func proto(facts ...plan.Fact) plan.Source {
	for i := range facts {
		facts[i].Message = "acme.v1.Individual"
	}
	return plan.SourceFunc(func(any) ([]plan.Fact, error) { return facts, nil })
}

// individualV1 is the schema before a rename.
func individualV1() plan.Source {
	return proto(
		plan.Fact{Field: "id", GoField: "Id", Number: 1, Kind: "int64"},
		plan.Fact{Field: "email", GoField: "Email", Number: 2, Kind: "string", Annotations: classified("user.contact.email")},
		plan.Fact{Field: "medicare_number", GoField: "MedicareNumber", Number: 3, Kind: "string", Annotations: classified("user.government_id")},
		plan.Fact{Field: "country", GoField: "Country", Number: 4, Kind: "string", Annotations: classified("system.operations")},
	)
}

// individualV2 is individualV1 with field 3 renamed.
func individualV2() plan.Source {
	return proto(
		plan.Fact{Field: "id", GoField: "Id", Number: 1, Kind: "int64"},
		plan.Fact{Field: "email", GoField: "Email", Number: 2, Kind: "string", Annotations: classified("user.contact.email")},
		plan.Fact{Field: "medicare_no", GoField: "MedicareNo", Number: 3, Kind: "string", Annotations: classified("user.government_id")},
		plan.Fact{Field: "country", GoField: "Country", Number: 4, Kind: "string", Annotations: classified("system.operations")},
	)
}

// record writes the snapshot of m over src to a fresh path and returns
// the path and what it wrote.
func record(t *testing.T, src plan.Source, m plan.Message) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "testdata", "TestPolicy.golden")
	logs, err := check(path, src, m, true, "RERUN")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, "wrote "+path) {
		t.Errorf("logs = %q, want the path written", logs)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, written
}

func mustContain(t *testing.T, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("passed, want a failure saying %q", wants)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("failure does not say %q:\n%s", want, err)
		}
	}
}

// The acceptance case: a renamed proto field with no pin fails with a
// context change, naming the pin; with the pin it passes, and the
// snapshot is the one checked in, byte for byte.
func TestRenameWithoutAPinIsAContextChange(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, before := record(t, individualV1(), m)

	_, err := check(path, individualV2(), m, false, "RERUN")
	mustContain(t, err,
		"CONTEXT CHANGES",
		`column medicare_number: no field writes its context "individuals/medicare_number" any more.`,
		`Field medicare_no (MedicareNo) now writes column medicare_no under "individuals/medicare_no"`,
		`Pinning the rule that decides field medicare_no (MedicareNo) with plan.Column("medicare_number") keeps it.`,
		"RERUN",
		"-  context individuals/medicare_number",
		"+  context individuals/medicare_no",
	)
	// A context change is data loss, not a migration. The new column is
	// still listed, since the guess may be wrong.
	if strings.Contains(err.Error(), "TARGET CHANGES") {
		t.Errorf("a rename is reported as a migration:\n%s", err)
	}
	mustContain(t, err, "OTHER CHANGES", "new column medicare_no, under \"individuals/medicare_no\", with terms [eq]. It is also named above as a possible rename of column medicare_number.")

	pinned := plan.ForMessage(nil, "individuals", plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality)), plan.Column("medicare_number")),
	).OrElse(base))
	if _, err := check(path, individualV2(), pinned, false, "RERUN"); err != nil {
		t.Fatalf("the pinned rename fails: %v", err)
	}
	after, _, err := take(individualV2(), pinned)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.render(), before) {
		t.Fatalf("the pinned rename changed the snapshot:\n%s\nwas\n%s", after.render(), before)
	}
}

// The same holds for a Go struct field renamed, where a fact source has
// no field number and the plan binds to the struct.
func TestStructFieldRename(t *testing.T) {
	type v1 struct {
		ID             int64
		MedicareNumber string `facts:"fides.data_categories=user.government_id"`
	}
	type v2 struct {
		ID         int64
		MedicareNo string `facts:"fides.data_categories=user.government_id"`
	}
	path, _ := record(t, factstest.StructTags, plan.ForMessage(v1{}, "individuals", base))
	_, err := check(path, factstest.StructTags, plan.ForMessage(v2{}, "individuals", base), false, "RERUN")
	mustContain(t, err, "CONTEXT CHANGES", `plan.Column("medicare_number")`)
	pinned := plan.ForMessage(v2{}, "individuals", plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality)), plan.Column("medicare_number")),
	).OrElse(base))
	if _, err := check(path, factstest.StructTags, pinned, false, "RERUN"); err != nil {
		t.Fatalf("the pinned rename fails: %v", err)
	}
}

// Each kind of change lands in its own section, with the advice that
// fits it.
func TestChangesAreSortedByWhatTheyCost(t *testing.T) {
	gov := plan.Encrypt(plan.EQL(se.Equality))
	for name, tc := range map[string]struct {
		before, after plan.Message
		src           plan.Source // individualV1 when nil
		section       string      // the section reported; "" when it does not build
		also          []string    // further sections reported
		says          []string
		never         []string // advice that would be wrong here
	}{
		"identity pin dropped": {
			before:  plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), gov, plan.Identity("medicare_no"))).OrElse(base)),
			after:   plan.ForMessage(nil, "individuals", base),
			section: "CONTEXT CHANGES",
			says:    []string{`column medicare_number: its context is "individuals/medicare_number", was "individuals/medicare_no".`, `with plan.Identity("medicare_no") keeps it.`},
		},
		"table changed": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "people", base),
			section: "CONTEXT CHANGES",
			says:    []string{`the message's table is people, was individuals.`, `restore plan.Table("individuals")`, `its context is "people/email", was "individuals/email". Restoring plan.Table("individuals") brings it back.`},
		},
		"table changed, nothing encrypted": {
			before:  plan.ForMessage(nil, "individuals", plan.When(category.Present(), plan.Plaintext())),
			after:   plan.ForMessage(nil, "people", plan.When(category.Present(), plan.Plaintext())),
			section: "OTHER CHANGES",
			says:    []string{"the message's table is people, was individuals. No context moves with it"},
		},
		"table changed, only Custom targets": {
			before:  plan.ForMessage(nil, "individuals", plan.When(category.Under("user"), plan.Encrypt(plan.Custom("pii/v1"))).OrElse(base)),
			after:   plan.ForMessage(nil, "people", plan.When(category.Under("user"), plan.Encrypt(plan.Custom("pii/v1"))).OrElse(base)),
			section: "OTHER CHANGES",
			says:    []string{"the message's table is people, was individuals. No context moves with it"},
		},
		"table and a table-shaped Custom context changed": {
			before:  plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Encrypt(plan.Custom("individuals/medicare_number")))).OrElse(base)),
			after:   plan.ForMessage(nil, "people", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Encrypt(plan.Custom("people/medicare_number")))).OrElse(base)),
			section: "CONTEXT CHANGES",
			says:    []string{`column medicare_number: its context is "people/medicare_number", was "individuals/medicare_number". No plan.Column or plan.Identity pin`},
			// Restoring the table leaves the Custom context as it is.
			never: []string{`was "individuals/medicare_number". Restoring`},
		},
		"table changed and field renamed": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "people", base),
			src:     individualV2(),
			section: "CONTEXT CHANGES",
			also:    []string{"OTHER CHANGES"},
			says:    []string{`Restoring plan.Table("individuals") and pinning the rule that decides field medicare_no (MedicareNo) with plan.Column("medicare_number") brings it back.`},
		},
		"target kind changed under the same context": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Encrypt(plan.Custom("individuals/medicare_number", se.Equality)))).OrElse(base)),
			section: "OTHER CHANGES",
			says:    []string{"column medicare_number: its target is Custom, was EQL, under the same context."},
		},
		"target kind and context changed": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Encrypt(plan.Custom("elsewhere/v1", se.Equality)))).OrElse(base)),
			section: "CONTEXT CHANGES",
			also:    []string{"OTHER CHANGES"},
			says: []string{
				`column medicare_number: its context is "elsewhere/v1", was "individuals/medicare_number".`,
				"column medicare_number: its target is Custom, was EQL.",
			},
			never: []string{"under the same context"},
		},
		"custom context changed": {
			before:  plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Encrypt(plan.Custom("gov/v1")))).OrElse(base)),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Encrypt(plan.Custom("gov/v2")))).OrElse(base)),
			section: "CONTEXT CHANGES",
			says:    []string{`its context is "gov/v2", was "gov/v1". No plan.Column or plan.Identity pin`, "a plan.Custom context"},
		},
		"encrypted now plaintext": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), plan.Plaintext())).OrElse(base)),
			section: "TARGET CHANGES",
			says:    []string{"column medicare_number is now field medicare_number, decided Plaintext.", `ciphertexts under "individuals/medicare_number"`},
		},
		"terms changed": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("email"), plan.Encrypt(plan.EQL(se.Equality)))).OrElse(base)),
			section: "TARGET CHANGES",
			says:    []string{"column email: its terms are [eq], were [eq match]."},
		},
		"plaintext now encrypted": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("country"), plan.Encrypt(plan.EQL()))).OrElse(base)),
			section: "TARGET CHANGES",
			says:    []string{`field country, decided Plaintext before, is now encrypted into column country under "individuals/country".`},
		},
		"database column renamed": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("medicare_number"), gov, plan.Column("medicare_num"), plan.Identity("medicare_number"))).OrElse(base)),
			section: "TARGET CHANGES",
			says:    []string{"column medicare_number is now stored in column medicare_num, under the same context"},
		},
		"field newly classified": {
			before:  plan.ForMessage(nil, "individuals", base),
			after:   plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("id"), plan.Encrypt(plan.EQL(se.Ore)))).OrElse(base)),
			section: "OTHER CHANGES",
			says:    []string{`new column id, under "individuals/id", with terms [ore].`},
		},
		"facts changed": {
			before: plan.ForMessage(nil, "individuals", base),
			after:  plan.ForMessage(nil, "individuals", base),
			src: proto(
				plan.Fact{Field: "email", GoField: "Email", Number: 2, Annotations: classified("user.contact.email", "user.contact.email.work")},
				plan.Fact{Field: "medicare_number", GoField: "MedicareNumber", Number: 3, Annotations: classified("user.government_id")},
				plan.Fact{Field: "country", GoField: "Country", Number: 4, Annotations: classified("system.operations", "system.location")},
			),
			section: "OTHER CHANGES",
			says: []string{
				"column email: its facts are [fides.data_categories=user.contact.email fides.data_categories=user.contact.email.work], were [fides.data_categories=user.contact.email].",
				"plaintext field country: its facts are",
			},
		},
		"plaintext field gone": {
			before: plan.ForMessage(nil, "individuals", base),
			after:  plan.ForMessage(nil, "individuals", base),
			src: proto(
				plan.Fact{Field: "email", GoField: "Email", Number: 2, Annotations: classified("user.contact.email")},
				plan.Fact{Field: "medicare_number", GoField: "MedicareNumber", Number: 3, Annotations: classified("user.government_id")},
			),
			section: "OTHER CHANGES",
			says:    []string{"plaintext field country is no longer decided by the policy"},
		},
		"refused": {
			before: plan.ForMessage(nil, "individuals", base),
			after:  plan.ForMessage(nil, "individuals", plan.FirstOf(plan.When(plan.Field("country"), plan.Fail("never stored"))).OrElse(base)),
			says:   []string{"the policy does not build", "never stored"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, _ := record(t, individualV1(), tc.before)
			src := tc.src
			if src == nil {
				src = individualV1()
			}
			_, err := check(path, src, tc.after, false, "RERUN")
			mustContain(t, err, tc.says...)
			for _, never := range tc.never {
				if strings.Contains(err.Error(), never) {
					t.Errorf("failure says %q:\n%s", never, err)
				}
			}
			if tc.section == "" {
				return
			}
			for _, s := range []string{"CONTEXT CHANGES", "TARGET CHANGES", "OTHER CHANGES"} {
				want := s == tc.section || slices.Contains(tc.also, s)
				if got := strings.Contains(err.Error(), s); got != want {
					t.Errorf("reports %s = %v, want %s and %v only:\n%s", s, got, tc.section, tc.also, err)
				}
			}
		})
	}
}

// A field removed from the schema without a trace is a lost context: the
// failure says what to do either way.
func TestALostContextWithNoCandidate(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, _ := record(t, individualV1(), m)
	gone := proto(
		plan.Fact{Field: "email", GoField: "Email", Number: 2, Annotations: classified("user.contact.email")},
		plan.Fact{Field: "country", GoField: "Country", Number: 4, Annotations: classified("system.operations")},
	)
	_, err := check(path, gone, m, false, "RERUN")
	mustContain(t, err, "CONTEXT CHANGES", `column medicare_number: no field writes its context "individuals/medicare_number" any more. If its field was renamed, pin the renamed field's rule with plan.Column("medicare_number")`)
}

// Custom columns may share a context, so a new one under the context of
// one that disappeared is no evidence of a database rename, and the
// context is not lost while another column still writes it.
func TestSharedCustomContextIsNotARename(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", plan.When(category.Under("user"), plan.Encrypt(plan.Custom("pii/v1"))))
	path, _ := record(t, proto(
		plan.Fact{Field: "a", GoField: "A", Number: 1, Annotations: classified("user.name")},
		plan.Fact{Field: "b", GoField: "B", Number: 2, Annotations: classified("user.name")},
	), m)
	_, err := check(path, proto(
		plan.Fact{Field: "b", GoField: "B", Number: 2, Annotations: classified("user.name")},
		plan.Fact{Field: "c", GoField: "C", Number: 3, Annotations: classified("user.content")},
	), m, false, "RERUN")
	mustContain(t, err, "OTHER CHANGES",
		`column a is no longer written. Its context "pii/v1" is not lost, since columns b, c still write it`,
		`new column c, under "pii/v1"`)
	for _, never := range []string{"RENAME COLUMN", "CONTEXT CHANGES"} {
		if strings.Contains(err.Error(), never) {
			t.Errorf("failure says %q:\n%s", never, err)
		}
	}
}

// An unrelated field added as another is removed, with the same facts,
// looks like a rename. The guess says it may be one, warns against the
// pin if it is not, and still lists the new column, so the developer can
// tell which it is.
func TestARenameGuessStatesTheOtherReading(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, _ := record(t, proto(
		plan.Fact{Field: "id", GoField: "Id", Number: 1},
		plan.Fact{Field: "home_phone", GoField: "HomePhone", Number: 2, Annotations: classified("user.contact.phone")},
	), m)
	_, err := check(path, proto(
		plan.Fact{Field: "id", GoField: "Id", Number: 1},
		plan.Fact{Field: "work_phone", GoField: "WorkPhone", Number: 3, Annotations: classified("user.contact.phone")},
	), m, false, "RERUN")
	mustContain(t, err,
		"CONTEXT CHANGES",
		`column home_phone: no field writes its context "individuals/home_phone" any more.`,
		`Field work_phone (WorkPhone) now writes column work_phone under "individuals/work_phone" with the same facts, so it may be the same field renamed:`,
		`with plan.Column("home_phone") keeps it.`,
		"If work_phone is instead a new field and home_phone was removed, do not pin it: that would store two fields in column home_phone under one context.",
		"OTHER CHANGES",
		`new column work_phone, under "individuals/work_phone", with terms [none]. It is also named above as a possible rename of column home_phone.`,
	)
	if strings.Contains(err.Error(), "likely") {
		t.Errorf("the guess is stated as likely:\n%s", err)
	}
}

// A Custom context that happens to be spelled like an identity is still
// Custom: the kind is not read off one sample.
func TestTargetKind(t *testing.T) {
	for _, tc := range []struct {
		target plan.Target
		want   string
	}{
		{plan.EQL(), kindEQL},
		{plan.EQL(se.Equality, se.Match), kindEQL},
		{plan.Custom("pii/v1"), kindCustom},
		{plan.Custom("plantest/a"), kindCustom},
		{plan.Custom("plantest/b"), kindCustom},
		{plan.Custom("plantest/probe"), kindCustom},
		{plan.Custom("individuals/email"), kindCustom},
	} {
		if got := targetKind(tc.target); got != tc.want {
			t.Errorf("targetKind(%v) = %s, want %s", tc.target, got, tc.want)
		}
	}
}

// Two new columns with the facts of the one that disappeared: no guess,
// and the generic advice.
func TestAmbiguousRenameIsNotGuessed(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, _ := record(t, individualV1(), m)
	split := proto(
		plan.Fact{Field: "email", GoField: "Email", Number: 2, Annotations: classified("user.contact.email")},
		plan.Fact{Field: "medicare_a", GoField: "MedicareA", Number: 5, Annotations: classified("user.government_id")},
		plan.Fact{Field: "medicare_b", GoField: "MedicareB", Number: 6, Annotations: classified("user.government_id")},
		plan.Fact{Field: "country", GoField: "Country", Number: 4, Annotations: classified("system.operations")},
	)
	_, err := check(path, split, m, false, "RERUN")
	mustContain(t, err, "If its field was renamed", "new column medicare_a", "new column medicare_b")
	if strings.Contains(err.Error(), "may be the same field renamed") {
		t.Errorf("guessed a rename between two candidates:\n%s", err)
	}
}

// The snapshot is the same whatever order the source gives fields and
// facts in, and from run to run.
func TestSnapshotIsDeterministic(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	a, _, err := take(individualV1(), m)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := proto(
		plan.Fact{Field: "country", GoField: "Country", Number: 4, Annotations: classified("system.operations")},
		plan.Fact{Field: "medicare_number", GoField: "MedicareNumber", Number: 3, Annotations: classified("user.government_id")},
		plan.Fact{Field: "email", GoField: "Email", Number: 2, Annotations: []plan.Annotation{
			{Key: "fides.data_categories", Values: []string{"user.contact.email"}},
			{Key: "fides.data_categories", Values: []string{"user.contact.email"}},
		}},
		plan.Fact{Field: "id", GoField: "Id", Number: 1},
	)
	b, _, err := take(shuffled, m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.render(), b.render()) {
		t.Fatalf("field or fact order changed the snapshot:\n%s\nvs\n%s", a.render(), b.render())
	}
	want := header + `
table individuals

column email
  context individuals/email
  target EQL
  terms eq match
  fact fides.data_categories user.contact.email

column medicare_number
  context individuals/medicare_number
  target EQL
  terms eq
  fact fides.data_categories user.government_id

plaintext country
  fact fides.data_categories system.operations
`
	if got := string(a.render()); got != want {
		t.Fatalf("snapshot =\n%s\nwant\n%s", got, want)
	}
}

// Whatever a name, a context or a fact holds, the snapshot reads back as
// what was written.
func TestSnapshotRoundTrips(t *testing.T) {
	odd := []string{"", "with space", `"quoted"`, "new\nline", "tab\there", "naïve", "#hash", "none", "a=b,c"}
	s := snapshot{table: "odd table"}
	for i, v := range odd {
		kind := kindEQL
		if i%2 == 1 {
			kind = kindCustom
		}
		// A plan never builds an empty context, and parse refuses one.
		context := v
		if context == "" {
			context = "t/empty"
		}
		s.columns = append(s.columns, column{name: v + string(rune('a'+i)), context: context, kind: kind, terms: []string{"eq", "ore"}, facts: []fact{{v, v}, {"k", v}}})
		s.plaintext = append(s.plaintext, plain{field: v + string(rune('a'+i)), facts: []fact{{v, "x"}}})
	}
	s.columns = append(s.columns, column{name: "bare", context: "t/bare", kind: kindEQL})
	for i := range s.columns {
		sortFacts(s.columns[i].facts)
	}
	s.sort()
	text := s.render()
	back, err := parse(text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if again := back.render(); !bytes.Equal(again, text) {
		t.Fatalf("round trip changed the snapshot:\n%s\nwas\n%s", again, text)
	}
	if !strings.Contains(string(text), "  terms none\n") {
		t.Errorf("an unindexed column does not say so:\n%s", text)
	}
}

func TestMissingSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testdata", "TestPolicy.golden")
	_, err := check(path, individualV1(), plan.ForMessage(nil, "individuals", base), false, "go test -run '^TestPolicy$' -update")
	mustContain(t, err, "no snapshot at "+path, "go test -run '^TestPolicy$' -update")
}

func TestUpdateRewritesAndSaysWhatItRecorded(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, _ := record(t, individualV1(), m)
	logs, err := check(path, individualV2(), m, true, "RERUN")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, "updated "+path) || !strings.Contains(logs, "CONTEXT CHANGES") {
		t.Errorf("logs = %q, want the update and the context change it recorded", logs)
	}
	if _, err := check(path, individualV2(), m, false, "RERUN"); err != nil {
		t.Fatalf("after -update: %v", err)
	}
	// Updating an unchanged snapshot is silent and leaves it alone.
	if logs, err := check(path, individualV2(), m, true, "RERUN"); err != nil || logs != "" {
		t.Errorf("no-op update: logs %q, err %v", logs, err)
	}
}

// A checkout that converted line endings still matches.
func TestCRLFCheckoutMatches(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, written := record(t, individualV1(), m)
	if err := os.WriteFile(path, bytes.ReplaceAll(written, []byte("\n"), []byte("\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := check(path, individualV1(), m, false, "RERUN"); err != nil {
		t.Fatal(err)
	}
}

func TestTextOnlyAndUnreadableSnapshots(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", base)
	path, written := record(t, individualV1(), m)

	// Same content, different text: still a failure, said as such.
	edited := bytes.Replace(written, []byte("table individuals"), []byte(`table "individuals"`), 1)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := check(path, individualV1(), m, false, "RERUN")
	mustContain(t, err, "Nothing the policy stores changed", `-table "individuals"`, "+table individuals")

	if err := os.WriteFile(path, append(written, []byte("garbage line\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = check(path, individualV1(), m, false, "RERUN")
	mustContain(t, err, "does not parse", `unexpected "garbage line"`, "+++ the policy now")
}

// parse refuses what render never writes, so a damaged snapshot falls back
// to the plain diff rather than a summary built on a misreading.
func TestParseRejects(t *testing.T) {
	const col = "\ncolumn email\n  context individuals/email\n  target EQL\n  terms eq\n"
	for name, tc := range map[string]struct{ text, says string }{
		"empty file":         {"", "no table line"},
		"header only":        {header, "no table line"},
		"no table line":      {header + col, "no table line"},
		"second table line":  {header + "\ntable individuals\ntable people\n" + col, `unexpected "table people"`},
		"unterminated quote": {header + "\ntable \"individuals\n", "bad quoted value"},
		"unknown target":     {header + "\ntable individuals\n" + strings.Replace(col, "target EQL", "target Mystery", 1), `unexpected "  target Mystery"`},
		"unknown line":       {header + "\ntable individuals\n" + col + "garbage line\n", `unexpected "garbage line"`},
		"column without a target": {
			header + "\ntable individuals\n" + strings.Replace(col, "  target EQL\n", "", 1),
			`column "email" has no context or target line`,
		},
		"column without a context": {
			header + "\ntable individuals\n" + strings.Replace(col, "  context individuals/email\n", "", 1),
			`column "email" has no context or target line`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse([]byte(tc.text))
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("parse error = %v, want one saying %q", err, tc.says)
			}
		})
	}
	// The complete column parses, so each case above fails for its own
	// reason.
	if _, err := parse([]byte(header + "\ntable individuals\n" + col)); err != nil {
		t.Errorf("the complete snapshot does not parse: %v", err)
	}
}

// A policy that does not build fails the test with the build's error.
func TestPolicyThatDoesNotBuild(t *testing.T) {
	narrow := plan.ForMessage(nil, "individuals", plan.When(category.Under("user.contact"), plan.Encrypt(plan.EQL())))
	_, err := check(filepath.Join(t.TempDir(), "x.golden"), individualV1(), narrow, true, "RERUN")
	if !errors.Is(err, plan.ErrUnmatched) {
		t.Fatalf("err = %v, want ErrUnmatched", err)
	}
	mustContain(t, err, "the policy does not build", "medicare_number")
	if _, err := check("x.golden", nil, narrow, true, "RERUN"); err == nil || !strings.Contains(err.Error(), "needs a Source") {
		t.Errorf("nil source: %v", err)
	}
}

// A message the policy encrypts nothing of has a snapshot: the fields it
// decided Plaintext.
func TestNothingEncrypted(t *testing.T) {
	m := plan.ForMessage(nil, "individuals", plan.When(category.Present(), plan.Plaintext()))
	_, written := record(t, individualV1(), m)
	if strings.Contains(string(written), "column ") || !strings.Contains(string(written), "plaintext medicare_number") {
		t.Fatalf("snapshot:\n%s", written)
	}
}

func TestGoldenPathAndRerun(t *testing.T) {
	for name, want := range map[string]string{
		"TestPolicy":                   filepath.Join("testdata", "TestPolicy.golden"),
		"TestPolicy/individuals":       filepath.Join("testdata", "TestPolicy", "individuals.golden"),
		"TestPolicy/v1.2+build_name-x": filepath.Join("testdata", "TestPolicy", "v1.2+build_name-x.golden"),
		"TestPolicy/CONSOLE":           filepath.Join("testdata", "TestPolicy", "CONSOLE.golden"),
		// Spelled differently, so hashed.
		"TestPolicy/a:b*c?":   filepath.Join("testdata", "TestPolicy", "a_b_c_~e7b9b9a8.golden"),
		"TestPolicy/..":       filepath.Join("testdata", "TestPolicy", "___~a3d4a70d.golden"),
		"TestPolicy/name.":    filepath.Join("testdata", "TestPolicy", "name_~19e5c1d8.golden"),
		"TestPolicy/name../x": filepath.Join("testdata", "TestPolicy", "name__~bab05642", "x.golden"),
		// Windows reserves device names, with any extension: the hash goes
		// before the first dot, so the stem is no longer one.
		"TestPolicy/CON":        filepath.Join("testdata", "TestPolicy", "CON~3367e86b.golden"),
		"TestPolicy/nul.golden": filepath.Join("testdata", "TestPolicy", "nul~80e138eb.golden.golden"),
		"TestPolicy/Com1.a.b":   filepath.Join("testdata", "TestPolicy", "Com1~14b3c4c0.a.b.golden"),
		"TestPolicy/LPT9":       filepath.Join("testdata", "TestPolicy", "LPT9~891f37a2.golden"),
		"AUX/individuals":       filepath.Join("testdata", "AUX~679e8439", "individuals.golden"),
	} {
		if got := goldenPath(name); got != want {
			t.Errorf("goldenPath(%q) = %q, want %q", name, got, want)
		}
	}
	// Names that differ only in what is respelled, or in a respelling and
	// what it is respelled to, keep their own snapshots.
	for _, pair := range [][2]string{{"T/a:b", "T/a?b"}, {"T/a:b", "T/a_b"}, {"T/CON", "T/CON_"}, {"T/x.", "T/x_"}, {"T/..", "T/___"}} {
		if a, b := goldenPath(pair[0]), goldenPath(pair[1]); a == b {
			t.Errorf("goldenPath(%q) and goldenPath(%q) are both %q", pair[0], pair[1], a)
		}
	}
	if got, want := rerun("TestPolicy/a.b"), `go test -run '^TestPolicy$/^a\.b$' -update`; got != want {
		t.Errorf("rerun = %s, want %s", got, want)
	}
}

func TestUpdateFlag(t *testing.T) {
	f := flag.Lookup("update")
	if f == nil {
		t.Fatal("-update is not registered")
	}
	if updating() {
		t.Skip("run with -update")
	}
	if err := f.Value.Set("true"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Value.Set("false") }()
	if !updating() {
		t.Error("updating() does not follow -update")
	}
}
