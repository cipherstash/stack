// Package individuals stores a type that carries no stash tags. A policy
// decides each field from the data categories the schema gives it.
package individuals

import (
	"context"
	"database/sql"

	"github.com/cipherstash/stack/languages/golang/stackencrypt"
	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

// Individual stands in for a type generated from a schema, such as a protobuf
// message, that cannot carry tags.
type Individual struct {
	ID         int64
	Name       string
	Email      string
	MedicareNo string
	Nickname   string
}

var category = plan.Key("fides.data_categories")

func categories(values ...string) []plan.Annotation {
	return []plan.Annotation{{Key: string(category), Values: values}}
}

// source states the facts a schema reader would produce. A protobuf source
// reads the same facts from descriptors and their custom options.
var source = plan.SourceFunc(func(msg any) ([]plan.Fact, error) {
	return []plan.Fact{
		{Field: "id", GoField: "ID"},
		{Field: "name", GoField: "Name", Annotations: categories("user.name")},
		{Field: "email", GoField: "Email", Annotations: categories("user.contact.email")},
		{Field: "medicare_no", GoField: "MedicareNo", Annotations: categories("user.government_id")},
		{Field: "nickname", GoField: "Nickname"},
	}, nil
})

var base = plan.FirstOf(
	plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(stackencrypt.Equality))),
	plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(stackencrypt.Equality, stackencrypt.Match()))),
	plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
)

var individuals = plan.ForMessage(&Individual{}, plan.Table("individuals"),
	plan.FirstOf(
		plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
			plan.Column("medicare_number")),
	).OrElse(base),
)

// The policy stores id and nickname as plaintext. The plan names them as
// omitted fields, so Bind accepts Individual.
var (
	individualsPlan = stackencrypt.MustBind[Individual](plan.MustPlanFor(source, individuals))
	medicarePlan    = stackencrypt.MustField[string](individualsPlan, "medicare_number")
)

func Create(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, person Individual) error {
	record, err := individualsPlan.Encrypt(ctx, cipher, person)
	if err != nil {
		return err
	}
	// Field returns an error for a name the plan does not have, never a zero
	// value that would write NULL.
	name, err := record.Field("name")
	if err != nil {
		return err
	}
	email, err := record.Field("email")
	if err != nil {
		return err
	}
	medicare, err := record.Field("medicare_number")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO individuals (id, nickname, name, email, email_eq, email_match, medicare_number, medicare_number_eq)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		person.ID, person.Nickname, name.Ciphertext, email.Ciphertext, email.Equality, email.Match,
		medicare.Ciphertext, medicare.Equality)
	return err
}

func IDByMedicare(ctx context.Context, db *sql.DB, cipher *stackencrypt.Cipher, medicareNo string) (int64, error) {
	term, err := medicarePlan.Equality(ctx, cipher, medicareNo)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRowContext(ctx, `SELECT id FROM individuals WHERE medicare_number_eq = $1`, term).Scan(&id)
	return id, err
}
