package users

//go:generate go tool stashgen -type User -row UserRows=UserRow -row SQLCUsers=userdb.User

// User's tags are the plan; stashgen writes user_stash.go from them. An
// exported field with no stash tag is refused, never stored unencrypted.
type User struct {
	_        struct{}       `stash:"context=users"`
	ID       int64          `stash:"id,passthrough"`
	Email    string         `stash:"email,encrypt,index=equality;match"`
	Age      uint32         `stash:"age,encrypt,index=equality;ore"`
	Attrs    map[string]any `stash:"attrs,index=json"`
	Notes    string         `stash:"notes,encrypt"`
	Internal string         `stash:"-"`
}
