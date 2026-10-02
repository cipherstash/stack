package plantest

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
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
	// A context change is data loss, not a migration or a new column.
	if strings.Contains(err.Error(), "TARGET CHANGES") || strings.Contains(err.Error(), "OTHER CHANGES") {
		t.Errorf("a rename is reported as more than a context change:\n%s", err)
	}

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
		section       string      // the only section reported; "" when it does not build
		says          []string
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
			if tc.section == "" {
				return
			}
			for _, s := range []string{"CONTEXT CHANGES", "TARGET CHANGES", "OTHER CHANGES"} {
				if got := strings.Contains(err.Error(), s); got != (s == tc.section) {
					t.Errorf("reports %s = %v, want only %s:\n%s", s, got, tc.section, err)
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
	if strings.Contains(err.Error(), "likely the same field renamed") {
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
  terms eq match
  fact fides.data_categories user.contact.email

column medicare_number
  context individuals/medicare_number
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
		s.columns = append(s.columns, column{name: v + string(rune('a'+i)), context: v, terms: []string{"eq", "ore"}, facts: []fact{{v, v}, {"k", v}}})
		s.plaintext = append(s.plaintext, plain{field: v + string(rune('a'+i)), facts: []fact{{v, "x"}}})
	}
	s.columns = append(s.columns, column{name: "bare", context: "t/bare"})
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
		"TestPolicy/a:b*c?":            filepath.Join("testdata", "TestPolicy", "a_b_c_.golden"),
		"TestPolicy/..":                filepath.Join("testdata", "TestPolicy", "___.golden"),
		"TestPolicy/v1.2+build_name-x": filepath.Join("testdata", "TestPolicy", "v1.2+build_name-x.golden"),
	} {
		if got := goldenPath(name); got != want {
			t.Errorf("goldenPath(%q) = %q, want %q", name, got, want)
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
