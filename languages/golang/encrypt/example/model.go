// Command example encrypts a batch of users against real ZeroKMS, using the
// credentials `stash auth login` leaves in the developer profile (or the
// CS_* environment variables, which win), and reads them back.
//
//	stash auth login
//	mise run go:encrypt:example       # builds both guests, then runs
//
// The struct's stash tags are the declaration; user_stash.go beside this
// file is what `go generate` wrote from them, and the program calls only
// the functions in it.
package main

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type User

// User is one row. Every exported field carries a stash tag, so a new field
// cannot reach the database unencrypted by accident.
type User struct {
	_     struct{} `stash:"context=users"`
	ID    int64    `stash:"id,passthrough"`
	Email string   `stash:"email,encrypt,index=equality;match"`
	Age   uint32   `stash:"age,encrypt,index=equality;ore"`
}
