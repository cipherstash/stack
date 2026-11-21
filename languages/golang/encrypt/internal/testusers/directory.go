package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Entry -name Entry

// Entry stores a name as EQL v4's TextSearch: one column that answers `=`,
// the orderings and `@@`. Its query carries only the term its operator
// reads, so `=` and `<` work on a one-letter name while `@@` on one is
// refused (ADR-0002, amended 2026-10-19).
type Entry struct {
	_    struct{} `stash:"context=directory"`
	ID   int64    `stash:"id,passthrough"`
	Name string   `stash:"name,encrypt_into=TextSearch"`
}
