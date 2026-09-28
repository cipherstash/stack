package stackencrypt_test

import (
	"bytes"
	"reflect"
	"testing"

	se "github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt/plan"
)

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
	individuals := plan.ForMessage(&individual{}, "individuals", plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality, se.Ore)), plan.Column("medicare_number")),
	).OrElse(base))

	fromPolicy := plan.MustPlanFor(plan.StructTags, individuals)
	// The schema spelling of each column, as a Rust derive or a database
	// would have it.
	byHand, err := se.NewPlan(
		se.FieldPlan{Field: "Email", Name: "email", Context: "individuals/email", Terms: []se.TermKind{se.Equality, se.Match}},
		se.FieldPlan{Field: "Name", Name: "name", Context: "individuals/name"},
		se.FieldPlan{Field: "MedicareNo", Name: "medicare_number", Context: "individuals/medicare_number", Terms: []se.TermKind{se.Equality, se.Ore}},
	)
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
			t.Fatalf("extension %v: guest input differs:\npolicy %x\nhand   %x", ext, a, b)
		}
	}
}
