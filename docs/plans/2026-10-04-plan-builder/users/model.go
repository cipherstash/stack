package users

import "github.com/cipherstash/stack/languages/golang/stackencrypt"

// User is the plaintext a caller works with. Its tags are the plan. PlanOf
// refuses an exported field with no stash tag, so a new field cannot reach the
// database unencrypted by accident.
type User struct {
	_        struct{}       `stash:"context=users"`
	ID       int64          `stash:"id,passthrough"`
	Email    string         `stash:"email,encrypt,index=equality;match"`
	Age      uint32         `stash:"age,encrypt,index=equality;ore"`
	Attrs    map[string]any `stash:"attrs,index=json"`
	Notes    string         `stash:"notes,encrypt"`
	Internal string         `stash:"-"`
}

// UserRow is the users table as stored. Every field is a driver.Valuer and an
// sql.Scanner. GORM's default naming maps EmailEq to email_eq; sqlx and scany
// read the db tags.
type UserRow struct {
	ID         int64                     `db:"id"          stash:"id"`
	Email      stackencrypt.Ciphertext   `db:"email"       stash:"email"`
	EmailEq    stackencrypt.EqualityTerm `db:"email_eq"    stash:"email,equality"`
	EmailMatch stackencrypt.MatchTerm    `db:"email_match" stash:"email,match"`
	Age        stackencrypt.Ciphertext   `db:"age"         stash:"age"`
	AgeEq      stackencrypt.EqualityTerm `db:"age_eq"      stash:"age,equality"`
	AgeOre     stackencrypt.OreTerm      `db:"age_ore"     stash:"age,ore"`
	Attrs      stackencrypt.JSONDocument `db:"attrs"       stash:"attrs,json"`
	Notes      stackencrypt.Ciphertext   `db:"notes"       stash:"notes"`
}

func (UserRow) TableName() string { return "users" }

// The plans are built and checked at package init. A bad tag, or a UserRow
// that does not cover every output of the plan, panics at startup instead of
// on the first request.
var (
	usersPlan   = stackencrypt.MustBind[User](stackencrypt.MustPlanOf[User]())
	userRowPlan = stackencrypt.MustRowPlan[UserRow](usersPlan)
	emailPlan   = stackencrypt.MustField[string](usersPlan, "email")
	agePlan     = stackencrypt.MustField[uint32](usersPlan, "age")
	attrsPlan   = stackencrypt.MustField[map[string]any](usersPlan, "attrs")
)
