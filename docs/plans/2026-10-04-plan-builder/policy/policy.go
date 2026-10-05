// Package policy decides what to encrypt from the data categories a schema
// gives each field. It runs in the generate program, never in the application.
package policy

import (
	"example.com/app/individuals"
	"github.com/cipherstash/stack/languages/golang/stackencrypt"
	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

var category = plan.Key("fides.data_categories")

func categories(values ...string) []plan.Annotation {
	return []plan.Annotation{{Key: string(category), Values: values}}
}

// Source states the facts a schema reader would produce. A protobuf source
// reads the same facts from descriptors and their custom options.
var Source = plan.SourceFunc(func(msg any) ([]plan.Fact, error) {
	return []plan.Fact{
		{Field: "id", GoField: "ID"},
		{Field: "name", GoField: "Name", Annotations: categories("user.name")},
		{Field: "email", GoField: "Email", Annotations: categories("user.contact.email")},
		{Field: "medicare_no", GoField: "MedicareNo", Annotations: categories("user.government_id")},
		{Field: "nickname", GoField: "Nickname"},
	}, nil
})

var Base = plan.FirstOf(
	plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(stackencrypt.Equality))),
	plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(stackencrypt.Equality, stackencrypt.Match()))),
	plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
)

var Individuals = plan.ForMessage(individuals.Individual{}, plan.Table("individuals"),
	plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
			plan.Column("medicare_number")),
	).OrElse(Base),
)
