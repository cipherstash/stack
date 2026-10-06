package plantest_test

import (
	"testing"

	se "github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/plan"
	"github.com/cipherstash/stack/languages/golang/encrypt/plan/plantest"
	"github.com/cipherstash/stack/languages/golang/internal/factstest"
)

var category = plan.Key("fides.data_categories")

type individual struct {
	ID         int64
	Email      string `facts:"fides.data_categories=user.contact.email"`
	Name       string `facts:"fides.data_categories=user.name"`
	MedicareNo string `facts:"fides.data_categories=user.government_id"`
	Notes      []byte `facts:"fides.data_categories=user.content"`
	Country    string `facts:"fides.data_categories=system.operations"`
}

// individuals has a field whose database column was renamed (stored in
// medicare_num, under its first identity), a Custom target, and a field
// left in plaintext.
var individuals = plan.ForMessage(&individual{}, plan.Table("individuals"), plan.FirstOf(
	plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(se.Equality)),
		plan.Column("medicare_num"), plan.Identity("medicare_number")),
	plan.When(category.Under("user.content"), plan.Encrypt(plan.Custom("individuals-notes/v1"))),
	plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(se.Equality, se.Match))),
	plan.When(category.Under("user"), plan.Encrypt(plan.EQL(se.Ore))),
	plan.When(category.Under("system"), plan.Plaintext()),
))

type audit struct {
	ID   int64
	Kind string `facts:"fides.data_categories=system.operations"`
}

// audits encrypts nothing: its snapshot is the fields it leaves plaintext.
var audits = plan.ForMessage(audit{}, plan.Table("audits"), plan.When(category.Under("system"), plan.Plaintext()))

// Each message's snapshot is checked in at testdata/TestPolicies/<name>.golden.
func TestPolicies(t *testing.T) {
	t.Run("individuals", func(t *testing.T) { plantest.Golden(t, factstest.StructTags, individuals) })
	t.Run("audits", func(t *testing.T) { plantest.Golden(t, factstest.StructTags, audits) })
}
