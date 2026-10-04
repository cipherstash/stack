package stackencrypt_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/factstest"
	se "github.com/cipherstash/stack/languages/golang/stackencrypt"
	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

// Validate refuses a nil type as PlanFromTags does, for the zero plan
// and a built one alike, rather than dereferencing it.
func TestValidateRefusesANilType(t *testing.T) {
	built, err := se.NewPlan(se.FieldPlan{Field: "A", Context: label(t, "t/a").Context()})
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]se.Plan{"zero": {}, "built": built} {
		if err := p.Validate(nil); err == nil || !strings.Contains(err.Error(), "nil type") {
			t.Errorf("%s plan: Validate(nil) = %v, want an error naming the nil type", name, err)
		}
	}
}

// A plan a policy builds is a Plan like any other: the guest receives
// byte-identical input to the equivalent plan built by hand. This test is
// here, not in package plan, because the guest encoding is unexported;
// plan imports stackencrypt, so only an external test can hold both.
func TestPolicyPlanIsTheHandBuiltPlan(t *testing.T) {
	type individual struct {
		ID         int64
		Email      string `facts:"fides.data_categories=user.contact.email"`
		Name       string `facts:"fides.data_categories=user.name"`
		MedicareNo string `facts:"fides.data_categories=user.government_id"`
		Country    string `facts:"fides.data_categories=system.operations"`
	}
	category := plan.Key("fides.data_categories")
	base := plan.FirstOf(
		plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(se.Equality))),
		plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(se.Equality, se.Match))),
		plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
		plan.When(category.Present(), plan.Plaintext()),
	)
	email := se.FieldPlan{Field: "Email", Name: "email", Context: label(t, "individuals/email").Context(), Terms: []se.TermKind{se.Equality, se.Match}}
	name := se.FieldPlan{Field: "Name", Name: "name", Context: label(t, "individuals/name").Context()}
	for label, tc := range map[string]struct {
		pins     []plan.RuleOption
		medicare se.FieldPlan
	}{
		// The schema spelling of each column, as a Rust derive or a
		// database would have it; Column alone sets the identity too.
		"column": {
			[]plan.RuleOption{plan.Column("medicare_number")},
			se.FieldPlan{Field: "MedicareNo", Name: "medicare_number", Context: label(t, "individuals/medicare_number").Context(), Terms: []se.TermKind{se.Equality, se.Ore}},
		},
		// After a database rename: the new column, the old identity.
		"renamed column": {
			[]plan.RuleOption{plan.Column("medicare_num"), plan.Identity("medicare_number")},
			se.FieldPlan{Field: "MedicareNo", Name: "medicare_num", Context: label(t, "individuals/medicare_number").Context(), Terms: []se.TermKind{se.Equality, se.Ore}},
		},
	} {
		individuals := plan.ForMessage(&individual{}, "individuals", plan.FirstOf(
			plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality, se.Ore)), tc.pins...),
		).OrElse(base))
		fromPolicy := plan.MustPlanFor(factstest.StructTags, individuals)
		byHand, err := se.NewPlan(email, name, tc.medicare)
		if err != nil {
			t.Fatal(err)
		}
		typ := reflect.TypeOf(individual{})
		for _, ext := range [][]any{nil, {uint64(7)}} {
			a, err := se.GuestPlanInput(fromPolicy, typ, ext...)
			if err != nil {
				t.Fatal(err)
			}
			b, err := se.GuestPlanInput(byHand, typ, ext...)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatalf("%s, extension %v: guest input differs:\npolicy %x\nhand   %x", label, ext, a, b)
			}
		}
	}
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
