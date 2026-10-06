// Package testusers holds the tagged structs the encrypt tests encrypt
// through the generated API: a record in separate columns, an opaque struct,
// and a probe struct with one field of each scalar type for the term
// ordering tests. The *_stash.go files beside them are what stashgen writes
// from the tags; `go generate ./...` rewrites them, and CI fails when that
// changes a file.
package testusers

import "github.com/cipherstash/stack/languages/golang/encrypt"

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type User -model Rows=UserRow

// User is the record of the Rust record fixture
// (packages/stack-encrypt/tests/fixtures/record_lowering.json): the same
// context, identities, kinds and indexes, so the fixture's records open
// through the generated code and its terms compare.
type User struct {
	_        struct{} `stash:"context=users"`
	ID       int64    `stash:"id,passthrough"`
	Age      uint32   `stash:"age,encrypt,index=equality;ore"`
	Email    string   `stash:"email,encrypt,index=equality;match"`
	Notes    string   `stash:"notes,encrypt"`
	Internal string   `stash:"-"`
}

// UserRow is a model for User in separate columns: one field for each
// output, each tagged with the output it holds, for a library that maps one
// struct field to one column.
type UserRow struct {
	ID         int64                `stash:"id"`
	Age        encrypt.Ciphertext   `stash:"age"`
	AgeEq      encrypt.EqualityTerm `stash:"age,equality"`
	AgeOre     encrypt.OreTerm      `stash:"age,ore"`
	Email      encrypt.Ciphertext   `stash:"email"`
	EmailEq    encrypt.EqualityTerm `stash:"email,equality"`
	EmailMatch encrypt.MatchTerm    `stash:"email,match"`
	Notes      encrypt.Ciphertext   `stash:"notes"`
}

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Document -name Document

// Document is sealed as one value.
type Document struct {
	_     struct{} `stash:"context=documents/v2/body,opaque"`
	Title string
	Body  string
	Tags  []string
}

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Probe -name Probe

// Probe has one field of each scalar type the ORE and OPE indexes order, for
// the property tests of term ordering.
type Probe struct {
	_   struct{} `stash:"context=prop"`
	U32 uint32   `stash:"u32,encrypt,index=ore;ope"`
	U64 uint64   `stash:"u64,encrypt,index=ore;ope"`
	I64 int64    `stash:"i64,encrypt,index=ore;ope"`
	S   string   `stash:"s,encrypt,index=ore;ope"`
	B   []byte   `stash:"b,encrypt,index=ore;ope"`
}
