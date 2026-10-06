package plan_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	se "github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/plan"
	"github.com/cipherstash/stack/languages/golang/internal/factstest"
)

var category = plan.Key("fides.data_categories")

var base = plan.FirstOf(
	plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(se.Equality))),
	plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(se.Equality, se.Match))),
	plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
)

type individual struct {
	ID         int64
	Email      string `facts:"fides.data_categories=user.contact.email"`
	Name       string `facts:"fides.data_categories=user.name"`
	MedicareNo string `facts:"fides.data_categories=user.government_id"`
	Country    string `facts:"fides.data_categories=system.operations"`
}

var individuals = plan.ForMessage(&individual{}, plan.Table("individuals"),
	plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality, se.Ore)), plan.Column("medicare_number")),
		plan.When(category.Under("system"), plan.Plaintext()),
	).OrElse(base),
)

func TestPolicyBuildsThePlan(t *testing.T) {
	p, err := plan.PlanFor(factstest.StructTags, individuals)
	if err != nil {
		t.Fatal(err)
	}
	// Columns are the schema's spelling of the Go field: what the Rust
	// derive binds and the database names.
	want := []se.FieldPlan{
		{Field: "Email", Name: "email", Context: label(t, "individuals/email").Context(), Terms: []se.TermKind{se.Equality, se.Match}},
		{Field: "Name", Name: "name", Context: label(t, "individuals/name").Context()},
		// The per-message rule wins over the base's government_id rule.
		{Field: "MedicareNo", Name: "medicare_number", Context: label(t, "individuals/medicare_number").Context(), Terms: []se.TermKind{se.Equality, se.Ore}},
	}
	if got := p.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields =\n%+v\nwant\n%+v", got, want)
	}
}

// A classified field no rule decides fails the build, naming the field and
// its facts, and every such field is reported.
func TestUnmatchedFactFailsTheBuild(t *testing.T) {
	type patient struct {
		ID          int64
		Fingerprint []byte `facts:"fides.data_categories=user.biometric.fingerprint"`
		Diagnosis   string `facts:"fides.data_categories=user.health"`
		Email       string `facts:"fides.data_categories=user.contact.email"`
	}
	narrow := plan.FirstOf(
		plan.When(category.Under("user.contact"), plan.Encrypt(plan.EQL(se.Equality))),
	)
	m := plan.ForMessage(patient{}, "patients", narrow)
	_, err := plan.PlanFor(factstest.StructTags, m)
	if !errors.Is(err, plan.ErrUnmatched) {
		t.Fatalf("err = %v, want ErrUnmatched", err)
	}
	for _, want := range []string{
		"fingerprint (Fingerprint)", "user.biometric.fingerprint",
		"diagnosis (Diagnosis)", "user.health",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "Email") || strings.Contains(err.Error(), ".id") {
		t.Errorf("error %q names a field that was decided or unclassified", err)
	}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustPlanFor did not panic on an unmatched fact")
			}
		}()
		plan.MustPlanFor(factstest.StructTags, m)
	}()

	// A catch-all written in the policy closes the gap; Plaintext counts.
	closed := plan.ForMessage(patient{}, "patients", narrow.OrElse(
		plan.When(category.Present(), plan.Plaintext()),
	))
	p := plan.MustPlanFor(factstest.StructTags, closed)
	if got := p.Fields(); len(got) != 1 || got[0].Field != "Email" {
		t.Fatalf("fields = %+v, want Email only", got)
	}
}

// A message the policy encrypts nothing of has no plan to build: the error
// says so, rather than encrypt's "at least one field".
func TestNothingEncryptedIsItsOwnError(t *testing.T) {
	type audit struct {
		ID   int64
		Kind string `facts:"fides.data_categories=system.operations"`
	}
	m := plan.ForMessage(audit{}, "audits", plan.When(category.Under("system"), plan.Plaintext()))
	_, err := plan.PlanFor(factstest.StructTags, m)
	if !errors.Is(err, plan.ErrNothingEncrypted) {
		t.Fatalf("err = %v, want ErrNothingEncrypted", err)
	}
	if !strings.Contains(err.Error(), "audit") || !strings.Contains(err.Error(), "needs no plan") {
		t.Errorf("error %q does not name the message and say what to do", err)
	}
}

// PlanFor binds the plan to the message's type: a fact naming a Go field
// the type does not have fails at build, not at the first record call.
func TestPlanForRefusesAFieldTheMessageDoesNotHave(t *testing.T) {
	facts := []plan.Fact{{Message: "acme.v1.Individual", Field: "email", GoField: "EMail",
		Annotations: []plan.Annotation{{Key: "k", Values: []string{"v"}}}}}
	src := plan.SourceFunc(func(any) ([]plan.Fact, error) { return facts, nil })
	m := plan.ForMessage(&individual{}, "individuals", plan.When(plan.Key("k").Present(), plan.Encrypt(plan.EQL())))
	_, err := plan.PlanFor(src, m)
	if err == nil || !strings.Contains(err.Error(), "EMail") || !strings.Contains(err.Error(), "not an exported field") {
		t.Fatalf("err = %v, want the unbound field named", err)
	}
	// With no message to bind to, Build alone cannot know, and does not try.
	if _, err := plan.ForMessage(nil, "individuals", plan.When(plan.Key("k").Present(), plan.Encrypt(plan.EQL()))).Build(facts); err != nil {
		t.Fatalf("Build with no message: %v", err)
	}
}

// An unclassified field is not the policy's concern, but a rule may still
// name it.
func TestUnclassifiedFieldsAreLeftOutUnlessNamed(t *testing.T) {
	facts := []plan.Fact{
		{Message: "acme.v1.Individual", Field: "id", GoField: "Id", Number: 1, Kind: "int64"},
		{Message: "acme.v1.Individual", Field: "notes", GoField: "Notes", Number: 2, Kind: "string"},
	}
	m := plan.ForMessage(nil, "individuals", plan.When(plan.Field("notes"), plan.Encrypt(plan.EQL())))
	p, err := m.Build(facts)
	if err != nil {
		t.Fatal(err)
	}
	want := []se.FieldPlan{{Field: "Notes", Name: "notes", Context: label(t, "individuals/notes").Context()}}
	if got := p.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields = %+v, want %+v", got, want)
	}
}

// A context is fixed at first write. Pinning the column keeps it, and the
// record key, through a field rename (proto or Go): on a column never
// renamed in the database, Column sets the identity too.
func TestColumnPinSurvivesRenames(t *testing.T) {
	gov := []plan.Annotation{{Key: "fides.data_categories", Values: []string{"user.government_id"}}}
	before := []plan.Fact{{Message: "acme.v1.Individual", Field: "medicare_number", GoField: "MedicareNumber", Annotations: gov}}
	after := []plan.Fact{{Message: "acme.v1.Individual", Field: "medicare_no", GoField: "MedicareNo", Annotations: gov}}

	v1 := plan.ForMessage(nil, "individuals", base)
	v2 := plan.ForMessage(nil, "individuals", plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality)), plan.Column("medicare_number")),
	).OrElse(base))

	p1, err := v1.Build(before)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := v2.Build(after)
	if err != nil {
		t.Fatal(err)
	}
	f1, f2 := p1.Fields()[0], p2.Fields()[0]
	want := label(t, "individuals/medicare_number").Context()
	if !f1.Context.Equal(want) || !f2.Context.Equal(f1.Context) {
		t.Fatalf("contexts %v, %v: want both individuals/medicare_number", f1.Context, f2.Context)
	}
	if f2.Name != "medicare_number" || f2.Field != "MedicareNo" {
		t.Fatalf("pinned field = %+v", f2)
	}
	// Without the pin, the rename would have changed the context.
	unpinned, err := v1.Build(after)
	if err != nil {
		t.Fatal(err)
	}
	if got := unpinned.Fields()[0].Context; !got.Equal(label(t, "individuals/medicare_no").Context()) {
		t.Fatalf("unpinned context = %v", got)
	}
}

// A database rename moves the record key, never the identity: new writes go
// to the new column, under the context existing rows were written with.
func TestIdentityKeepsTheContextThroughAColumnRename(t *testing.T) {
	gov := []plan.Annotation{{Key: "fides.data_categories", Values: []string{"user.government_id"}}}
	facts := []plan.Fact{{Message: "acme.v1.Individual", Field: "medicare_no", GoField: "MedicareNo", Annotations: gov}}
	eq := plan.Encrypt(plan.EQL(se.Equality))
	for name, tc := range map[string]struct {
		opts         []plan.RuleOption
		key, context string
	}{
		// Neither: both are the field's schema name.
		"defaults": {nil, "medicare_no", "individuals/medicare_no"},
		// Column alone, on a field never renamed in the database: both.
		"column": {[]plan.RuleOption{plan.Column("medicare_number")}, "medicare_number", "individuals/medicare_number"},
		// ALTER TABLE individuals RENAME COLUMN medicare_number TO medicare_num.
		"renamed column": {[]plan.RuleOption{plan.Column("medicare_num"), plan.Identity("medicare_number")}, "medicare_num", "individuals/medicare_number"},
		// The column renamed to the field's own name.
		"identity alone": {[]plan.RuleOption{plan.Identity("medicare_number")}, "medicare_no", "individuals/medicare_number"},
	} {
		p, err := plan.ForMessage(nil, "individuals", plan.When(plan.Field("medicare_no"), eq, tc.opts...)).Build(facts)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want := []se.FieldPlan{{Field: "MedicareNo", Name: tc.key, Context: label(t, tc.context).Context(), Terms: []se.TermKind{se.Equality}}}
		if got := p.Fields(); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: fields = %+v, want %+v", name, got, want)
		}
	}
}

func TestContextsByTarget(t *testing.T) {
	facts := []plan.Fact{
		{Field: "email", GoField: "Email", Annotations: []plan.Annotation{{Key: "k", Values: []string{"eql"}}}},
		{Field: "blob", GoField: "Blob", Annotations: []plan.Annotation{{Key: "k", Values: []string{"custom"}}}},
	}
	k := plan.Key("k")
	m := plan.ForMessage(nil, "users", plan.FirstOf(
		plan.When(k.Is("eql"), plan.Encrypt(plan.EQL(se.Equality))),
		plan.When(k.Is("custom"), plan.Encrypt(plan.Custom("tenant-blobs/v1", se.Ope)), plan.Column("blob_v1")),
	))
	p, err := m.Build(facts)
	if err != nil {
		t.Fatal(err)
	}
	want := []se.FieldPlan{
		{Field: "Email", Name: "email", Context: label(t, "users/email").Context(), Terms: []se.TermKind{se.Equality}},
		// A custom target's context is its own; the pin names the record key only.
		{Field: "Blob", Name: "blob_v1", Context: label(t, "tenant-blobs/v1").Context(), Terms: []se.TermKind{se.Ope}},
	}
	if got := p.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields =\n%+v\nwant\n%+v", got, want)
	}
	// A '/' in a custom target's column is only a '/' in a record key: no
	// identity to make ambiguous.
	slashed := plan.ForMessage(nil, "users", plan.When(k.Is("custom"), plan.Encrypt(plan.Custom("tenant-blobs/v1")), plan.Column("blob/v1")))
	p, err = slashed.Build(facts[1:])
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Fields()[0].Name; got != "blob/v1" {
		t.Errorf("custom record key = %q, want blob/v1", got)
	}
}

func TestBuildRefusesMalformedDecisions(t *testing.T) {
	classified := []plan.Annotation{{Key: "k", Values: []string{"v"}}}
	fact := []plan.Fact{{Field: "a", Annotations: classified}}
	// Each case fails for its own reason: a sentinel, or the message the
	// reason is spelled by where encrypt reports it.
	for name, tc := range map[string]struct {
		table  plan.Table
		policy plan.Policy
		want   error
		msg    string
	}{
		"no table":           {"", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())), nil, "needs a Table"},
		"slash in table":     {"a/b", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())), nil, "contains '/'"},
		"slash in column":    {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()), plan.Column("x/y")), plan.ErrInvalid, "contains '/'"},
		"empty field name":   {"t", plan.When(plan.Kind(""), plan.Encrypt(plan.EQL())), plan.ErrInvalid, "no name"},
		"fail":               {"t", plan.When(plan.Field("a"), plan.Fail("biometrics are never stored")), plan.ErrRefused, ""},
		"nil target":         {"t", plan.When(plan.Field("a"), plan.Encrypt(nil)), plan.ErrInvalid, "no target"},
		"column on plain":    {"t", plan.When(plan.Field("a"), plan.Plaintext(), plan.Column("c")), plan.ErrInvalid, "Plaintext"},
		"identity on plain":  {"t", plan.When(plan.Field("a"), plan.Plaintext(), plan.Identity("c")), plan.ErrInvalid, "Plaintext"},
		"identity on custom": {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.Custom("t/ctx")), plan.Identity("c")), plan.ErrInvalid, "context is fixed"},
		"one-part custom":    {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.Custom("ctx"))), nil, "one part, not a label"},
		"unplain custom":     {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.Custom("t/7up"))), plan.ErrInvalid, "is not a label"},
		"slash in identity":  {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()), plan.Column("c"), plan.Identity("x/y")), plan.ErrInvalid, "contains '/'"},
		// Identifier.Label() refuses more than '/': every reason a segment is
		// not plain, named as the table or the column identity it came from.
		"digit in table":     {"2024_events", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())), plan.ErrInvalid, `table "2024_events"`},
		"digit in column":    {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()), plan.Column("2fa_secret")), plan.ErrInvalid, `column identity "2fa_secret"`},
		"b64 in column":      {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()), plan.Column("b64:x")), plan.ErrInvalid, "another descriptor form"},
		"paren in column":    {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()), plan.Column("a(b")), plan.ErrInvalid, "reserves"},
		"invisible in table": {"users\u200b", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())), plan.ErrInvalid, "invisible"},
		"zero decision":      {"t", plan.When(plan.Field("a"), plan.Decision{}), plan.ErrInvalid, "zero Decision"},
		"empty context":      {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.Custom(""))), plan.ErrInvalid, "empty context"},
		"nil policy":         {"t", nil, plan.ErrUnmatched, ""},
		"nothing encrypted":  {"t", plan.When(plan.Field("a"), plan.Plaintext()), plan.ErrNothingEncrypted, "needs no plan"},
		"term kind unknown":  {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL(se.TermKind(9)))), nil, "unknown term kind"},
		"nil policies skip":  {"t", plan.FirstOf(nil, nil), plan.ErrUnmatched, ""},
		"fail names reason":  {"t", plan.When(plan.Field("a"), plan.Fail("no biometrics")), plan.ErrRefused, "no biometrics"},
		"matcher composites": {"t", plan.When(plan.All(plan.Field("a"), plan.Not(plan.Kind("string"))), plan.Fail("x")), plan.ErrRefused, ""},
	} {
		facts := fact
		if name == "empty field name" {
			facts = []plan.Fact{{Field: "", Annotations: classified}}
		}
		_, err := plan.ForMessage(nil, tc.table, tc.policy).Build(facts)
		if err == nil {
			t.Errorf("%s: built", name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
		if tc.msg != "" && !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: err = %q, want it to say %q", name, err, tc.msg)
		}
	}
	_, err := plan.ForMessage(nil, "t", plan.When(plan.Field("a"), plan.Fail("no biometrics"))).Build(fact)
	if !strings.Contains(err.Error(), "no biometrics") {
		t.Errorf("fail error %q does not carry its reason", err)
	}
	// Two fields pinned to one column are one record name twice.
	two := []plan.Fact{{Field: "a", Annotations: classified}, {Field: "b", Annotations: classified}}
	if _, err := plan.ForMessage(nil, "t", plan.When(plan.Any(plan.Field("a"), plan.Field("b")), plan.Encrypt(plan.EQL()), plan.Column("c"))).Build(two); err == nil {
		t.Error("two fields pinned to one column built")
	}
	// Two columns with one identity would bind each other's ciphertexts.
	_, err = plan.ForMessage(nil, "t", plan.FirstOf(
		plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())),
		plan.When(plan.Field("b"), plan.Encrypt(plan.EQL()), plan.Identity("a")),
	)).Build(two)
	if !errors.Is(err, plan.ErrInvalid) || !strings.Contains(err.Error(), `identity "a" is already field a's`) {
		t.Errorf("two fields sharing an identity: err = %v", err)
	}
	// Custom targets may share a context: it is the policy's to choose, and
	// the guest, not NewPlan, refuses two fields under one label when a
	// record call runs.
	if _, err := plan.ForMessage(nil, "t", plan.When(plan.Any(plan.Field("a"), plan.Field("b")), plan.Encrypt(plan.Custom("blobs/ctx")))).Build(two); err != nil {
		t.Errorf("two custom fields sharing a context: %v", err)
	}
}

func TestKeyMatchers(t *testing.T) {
	f := plan.Fact{Annotations: []plan.Annotation{
		{Key: "fides.data_categories", Values: []string{"user.contactless", "user.contact.email"}},
		{Key: "other", Values: []string{"x"}},
	}}
	for m, want := range map[string]bool{
		"user":                    true,
		"user.contact":            true,
		"user.contact.email":      true,
		"user.contact.email.work": false,
		"user.contac":             false,
		"system":                  false,
	} {
		if got := category.Under(m)(f); got != want {
			t.Errorf("Under(%q) = %v, want %v", m, got, want)
		}
	}
	if !category.Is("user.contactless")(f) || category.Is("user")(f) {
		t.Error("Is matches other than exactly")
	}
	if !plan.Key("other").Present()(f) || plan.Key("absent").Present()(f) {
		t.Error("Present")
	}
	if got := f.Values("other"); !reflect.DeepEqual(got, []string{"x"}) {
		t.Errorf("Values = %v", got)
	}
	// A prefix that could read as a catch-all but match nothing is refused
	// when the rule is written, not silently dead.
	for _, prefix := range []string{"", "user.", ".user", "a..b"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Under(%q) did not panic", prefix)
				}
			}()
			category.Under(prefix)
		}()
	}
}

// The combinators refuse a nil matcher when the rule is written, as When
// does, naming the combinator; and they hold their own copy of the
// matchers, so a later write to the caller's slice changes nothing.
func TestCombinatorsRefuseNilAndCopyTheirMatchers(t *testing.T) {
	var unset plan.Matcher
	for name, build := range map[string]func(){
		"Any": func() { plan.Any(plan.Field("a"), unset) },
		"All": func() { plan.All(unset) },
		"Not": func() { plan.Not(unset) },
		// With no matchers, All would match every field and Any none: a
		// rule built from an empty slice would silently decide everything
		// or nothing.
		"Any()": func() { plan.Any() },
		"All()": func() { plan.All([]plan.Matcher{}...) },
	} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("%s did not panic", name)
				} else if !strings.Contains(fmt.Sprint(r), "plan."+strings.TrimSuffix(name, "()")) {
					t.Errorf("%s panicked with %v, which does not name it", name, r)
				}
			}()
			build()
		}()
	}
	ms := []plan.Matcher{plan.Field("a")}
	any, all := plan.Any(ms...), plan.All(ms...)
	ms[0] = plan.Field("b")
	a, b := plan.Fact{Field: "a"}, plan.Fact{Field: "b"}
	if !any(a) || any(b) || !all(a) || all(b) {
		t.Error("a write to the caller's slice changed the matcher")
	}
}

func TestPinsRefuseAnEmptyName(t *testing.T) {
	for name, pin := range map[string]func(string) plan.RuleOption{"Column": plan.Column, "Identity": plan.Identity} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s(\"\") did not panic", name)
				}
			}()
			pin("")
		}()
	}
}

func TestDecisionsSpellThemselves(t *testing.T) {
	d, ok := plan.When(plan.Field("a"), plan.Encrypt(plan.EQL(se.Equality, se.Match)), plan.Column("c"), plan.Identity("old_c")).Decide(plan.Fact{Field: "a"})
	if !ok {
		t.Fatal("no match")
	}
	if got, want := d.String(), `Encrypt(EQL(eq, match)) Column("c") Identity("old_c")`; got != want {
		t.Errorf("String = %s, want %s", got, want)
	}
	if target, ok := d.Target(); !ok || target == nil || d.Column() != "c" || d.Identity() != "old_c" {
		t.Errorf("accessors: %v %v %q %q", target, ok, d.Column(), d.Identity())
	}
	if d := plan.Encrypt(plan.EQL()); d.Column() != "" || d.Identity() != "" {
		t.Errorf("unpinned accessors: %q %q", d.Column(), d.Identity())
	}
	for d, want := range map[string]string{
		plan.Plaintext().String():                         "Plaintext()",
		plan.Fail("no").String():                          `Fail("no")`,
		plan.Encrypt(plan.Custom("ctx", se.Ope)).String(): `Encrypt(Custom("ctx", ope))`,
		plan.Encrypt(plan.Custom("ctx")).String():         `Encrypt(Custom("ctx"))`,
		plan.Decision{}.String():                          "Decision{}",
	} {
		if d != want {
			t.Errorf("String = %s, want %s", d, want)
		}
	}
	if _, ok := plan.Plaintext().Target(); ok {
		t.Error("Plaintext has a target")
	}
}

func TestFactAndSource(t *testing.T) {
	f := plan.Fact{Message: "row", Field: "email", GoField: "Email", Annotations: []plan.Annotation{
		{Key: "a", Values: []string{"x", "y"}}, {Key: "b", Values: []string{"z"}}, {Key: "a", Values: []string{"w"}},
	}}
	if got := f.String(); got != "row.email (Email) [a=x,y; b=z; a=w]" {
		t.Errorf("String = %s", got)
	}
	if got := f.Values("a"); !reflect.DeepEqual(got, []string{"x", "y", "w"}) {
		t.Errorf("Values = %v", got)
	}
	src := plan.SourceFunc(func(any) ([]plan.Fact, error) { return []plan.Fact{f}, nil })
	if got, err := src.Facts(nil); err != nil || len(got) != 1 {
		t.Errorf("SourceFunc.Facts = %v, %v", got, err)
	}
	if _, err := plan.PlanFor(nil, individuals); err == nil {
		t.Error("PlanFor without a source")
	}
	if individuals.Table() != "individuals" || individuals.Msg() == nil {
		t.Error("Message accessors")
	}
}

func TestWhenRefusesANilMatcher(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("When(nil, ...) did not panic")
		}
	}()
	plan.When(nil, plan.Plaintext())
}

// label is se.ParseLabel for a label the test knows to be valid.
func label(t testing.TB, s string) se.Label {
	t.Helper()
	l, err := se.ParseLabel(s)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// With the identity pinned, the storage column is only the record key, as a
// Custom target's is: a '/' in it names a database column, not a context, so
// it is accepted and the context stays the pinned identity's label.
func TestASlashInARenamedStorageColumnIsOnlyARecordKey(t *testing.T) {
	facts := []plan.Fact{{Field: "blob", GoField: "Blob", Annotations: []plan.Annotation{{Key: "k", Values: []string{"v"}}}}}
	p, err := plan.ForMessage(nil, "t", plan.When(plan.Field("blob"), plan.Encrypt(plan.EQL()), plan.Column("blob/v1"), plan.Identity("blob"))).Build(facts)
	if err != nil {
		t.Fatal(err)
	}
	f := p.Fields()[0]
	if f.Name != "blob/v1" || !f.Context.Equal(label(t, "t/blob").Context()) {
		t.Fatalf("field = %+v, want record key blob/v1 under t/blob", f)
	}
}

// The label error survives the wrapping, so a caller can learn which half
// of the identifier was wrong rather than only that the decision is invalid.
func TestABadIdentifierKeepsItsLabelError(t *testing.T) {
	facts := []plan.Fact{{Field: "a", Annotations: []plan.Annotation{{Key: "k", Values: []string{"v"}}}}}
	_, err := plan.ForMessage(nil, "a/b", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()))).Build(facts)
	var le *se.LabelError
	if !errors.Is(err, plan.ErrInvalid) || !errors.As(err, &le) || le.Index != 0 {
		t.Fatalf("err = %v; want ErrInvalid wrapping a LabelError for segment 0", err)
	}
	if !strings.Contains(err.Error(), `table "a/b"`) {
		t.Errorf("err = %v; want the table named", err)
	}
}

// Only an EQL target's context is built from the table, so a message whose
// every encrypted field has a Custom target builds with a table name that
// would not be a plain segment. Recorded, not endorsed: the table is unused
// by such a field's context.
func TestACustomOnlyMessageTakesAnyTableName(t *testing.T) {
	facts := []plan.Fact{{Field: "a", Annotations: []plan.Annotation{{Key: "k", Values: []string{"v"}}}}}
	p, err := plan.ForMessage(nil, "a/b", plan.When(plan.Field("a"), plan.Encrypt(plan.Custom("blobs/ctx")))).Build(facts)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Fields()[0].Context; !got.Equal(label(t, "blobs/ctx").Context()) {
		t.Errorf("context = %v, want the custom label", got)
	}
}
