package plan_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	se "github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt/plan"
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
		plan.When(plan.Field("MedicareNo"), plan.Encrypt(plan.EQL(se.Equality, se.Ore)), plan.Column("medicare_number")),
		plan.When(category.Under("system"), plan.Plaintext()),
	).OrElse(base),
)

func TestPolicyBuildsThePlan(t *testing.T) {
	p, err := plan.PlanFor(plan.StructTags, individuals)
	if err != nil {
		t.Fatal(err)
	}
	want := []se.FieldPlan{
		{Field: "Email", Name: "Email", Context: "individuals/Email", Terms: []se.TermKind{se.Equality, se.Match}},
		{Field: "Name", Name: "Name", Context: "individuals/Name"},
		// The per-message rule wins over the base's government_id rule.
		{Field: "MedicareNo", Name: "medicare_number", Context: "individuals/medicare_number", Terms: []se.TermKind{se.Equality, se.Ore}},
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
	_, err := plan.PlanFor(plan.StructTags, m)
	if !errors.Is(err, plan.ErrUnmatched) {
		t.Fatalf("err = %v, want ErrUnmatched", err)
	}
	for _, want := range []string{
		"Fingerprint", "user.biometric.fingerprint",
		"Diagnosis", "user.health",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "Email") || strings.Contains(err.Error(), ".ID") {
		t.Errorf("error %q names a field that was decided or unclassified", err)
	}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustPlanFor did not panic on an unmatched fact")
			}
		}()
		plan.MustPlanFor(plan.StructTags, m)
	}()

	// A catch-all written in the policy closes the gap; Plaintext counts.
	closed := plan.ForMessage(patient{}, "patients", narrow.OrElse(
		plan.When(category.Present(), plan.Plaintext()),
	))
	p := plan.MustPlanFor(plan.StructTags, closed)
	if got := p.Fields(); len(got) != 1 || got[0].Field != "Email" {
		t.Fatalf("fields = %+v, want Email only", got)
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
	want := []se.FieldPlan{{Field: "Notes", Name: "notes", Context: "individuals/notes"}}
	if got := p.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields = %+v, want %+v", got, want)
	}
}

// A context is fixed at first write. Pinning the column keeps it through a
// field rename (proto or Go) and is the identity a database rename keeps.
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
	if f1.Context != "individuals/medicare_number" || f2.Context != f1.Context {
		t.Fatalf("contexts %q, %q: want both individuals/medicare_number", f1.Context, f2.Context)
	}
	if f2.Name != "medicare_number" || f2.Field != "MedicareNo" {
		t.Fatalf("pinned field = %+v", f2)
	}
	// Without the pin, the rename would have changed the context.
	unpinned, err := v1.Build(after)
	if err != nil {
		t.Fatal(err)
	}
	if got := unpinned.Fields()[0].Context; got != "individuals/medicare_no" {
		t.Fatalf("unpinned context = %q", got)
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
		{Field: "Email", Name: "email", Context: "users/email", Terms: []se.TermKind{se.Equality}},
		// A custom target's context is its own; the pin names the record key only.
		{Field: "Blob", Name: "blob_v1", Context: "tenant-blobs/v1", Terms: []se.TermKind{se.Ope}},
	}
	if got := p.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields =\n%+v\nwant\n%+v", got, want)
	}
}

func TestBuildRefusesMalformedDecisions(t *testing.T) {
	classified := []plan.Annotation{{Key: "k", Values: []string{"v"}}}
	fact := []plan.Fact{{Field: "a", Annotations: classified}}
	for name, tc := range map[string]struct {
		table  plan.Table
		policy plan.Policy
		want   error
	}{
		"no table":           {"", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())), nil},
		"slash in table":     {"a/b", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL())), nil},
		"slash in column":    {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL()), plan.Column("x/y")), plan.ErrInvalid},
		"fail":               {"t", plan.When(plan.Field("a"), plan.Fail("biometrics are never stored")), plan.ErrRefused},
		"nil target":         {"t", plan.When(plan.Field("a"), plan.Encrypt(nil)), plan.ErrInvalid},
		"column on plain":    {"t", plan.When(plan.Field("a"), plan.Plaintext(), plan.Column("c")), plan.ErrInvalid},
		"zero decision":      {"t", plan.When(plan.Field("a"), plan.Decision{}), plan.ErrInvalid},
		"empty context":      {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.Custom(""))), plan.ErrInvalid},
		"nil policy":         {"t", nil, plan.ErrUnmatched},
		"nothing encrypted":  {"t", plan.When(plan.Field("a"), plan.Plaintext()), nil},
		"term kind unknown":  {"t", plan.When(plan.Field("a"), plan.Encrypt(plan.EQL(se.TermKind(9)))), nil},
		"nil policies skip":  {"t", plan.FirstOf(nil, nil), plan.ErrUnmatched},
		"fail names reason":  {"t", plan.When(plan.Field("a"), plan.Fail("no biometrics")), plan.ErrRefused},
		"matcher composites": {"t", plan.When(plan.All(plan.Field("a"), plan.Not(plan.Kind("string"))), plan.Fail("x")), plan.ErrRefused},
	} {
		_, err := plan.ForMessage(nil, tc.table, tc.policy).Build(fact)
		if err == nil {
			t.Errorf("%s: built", name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
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
}

func TestDecisionsSpellThemselves(t *testing.T) {
	d, ok := plan.When(plan.Field("a"), plan.Encrypt(plan.EQL(se.Equality, se.Match)), plan.Column("c")).Decide(plan.Fact{Field: "a"})
	if !ok {
		t.Fatal("no match")
	}
	if got, want := d.String(), `Encrypt(EQL(eq, match)) Column("c")`; got != want {
		t.Errorf("String = %s, want %s", got, want)
	}
	if target, ok := d.Target(); !ok || target == nil || d.Column() != "c" {
		t.Errorf("accessors: %v %v %q", target, ok, d.Column())
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

func TestStructTagsSource(t *testing.T) {
	type embedded struct{ Inner string }
	type row struct {
		embedded
		ID     *int64
		Email  string `facts:"a=x,y;b=z"`
		hidden string //nolint:unused // proves unexported fields are skipped
	}
	facts, err := plan.StructTags.Facts(&row{})
	if err != nil {
		t.Fatal(err)
	}
	want := []plan.Fact{
		{Message: "plan_test.row", Field: "ID", GoField: "ID", Kind: "int64"},
		{Message: "plan_test.row", Field: "Email", GoField: "Email", Kind: "string", Annotations: []plan.Annotation{
			{Key: "a", Values: []string{"x", "y"}}, {Key: "b", Values: []string{"z"}},
		}},
	}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("facts =\n%+v\nwant\n%+v", facts, want)
	}
	if got := facts[1].String(); got != "plan_test.row.Email [a=x,y; b=z]" {
		t.Errorf("String = %s", got)
	}
	for name, bad := range map[string]any{
		"not a struct": 42,
		"nil":          nil,
		"no value": struct {
			A string `facts:"a="`
		}{},
		"no key": struct {
			A string `facts:"=x"`
		}{},
		"empty value": struct {
			A string `facts:"a=x,"`
		}{},
		"key twice": struct {
			A string `facts:"a=x;a=y"`
		}{},
	} {
		if _, err := plan.StructTags.Facts(bad); err == nil {
			t.Errorf("%s: facts read", name)
		}
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
