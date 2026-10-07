package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Contact -name Contact

// Contact is one row with an email stored as an EQL value, the shape the
// cross-language fixture packages/eql/tests/encryption/fixtures/text_eq_query.json
// is derived under (table users, column email). Its generated file imports
// encrypt/eql, so the encrypt test binary links the guest build with the
// EQL types; the tests that want the build without them load it by name.
type Contact struct {
	_     struct{} `stash:"context=users"`
	ID    int64    `stash:"id,passthrough"`
	Email string   `stash:"email,encrypt_into=TextEq"`
	Notes string   `stash:"notes,encrypt"`
}
