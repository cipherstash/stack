package users

//go:generate go tool stashgen -type User

// Every exported field needs a stash tag, so a new field cannot reach the
// database unencrypted by accident.
type User struct {
	_        struct{} `stash:"context=users"`
	ID       int64    `stash:"id,passthrough" db:"id" gorm:"primaryKey"`
	Email    string   `stash:"email,encrypt_into=TextEq" db:"email"`
	Name     string   `stash:"name,encrypt_into=TextEq" db:"name"`
	Internal string   `stash:"-"`
}
