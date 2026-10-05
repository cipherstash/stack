package users

//go:generate go tool stashgen -type User

// Every exported field needs a stash tag, so a new field cannot reach the
// database unencrypted by accident.
type User struct {
	_        struct{}       `stash:"context=users"`
	ID       int64          `stash:"id,passthrough" db:"id" gorm:"primaryKey"`
	Email    string         `stash:"email,encrypt_into=TextSearch" db:"email"`
	Age      int32          `stash:"age,encrypt_into=IntegerOrd" db:"age"`
	Attrs    map[string]any `stash:"attrs,encrypt_into=JSON" db:"attrs"`
	Notes    string         `stash:"notes,encrypt_into=Text" db:"notes"`
	Internal string         `stash:"-"`
}
