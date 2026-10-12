package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Profile -name Profile

// Profile stores one field in each EQL v4 type the engine produces besides
// TextEq, the shape the cross-language fixtures under
// packages/eql/tests/encryption/fixtures (v4_queries.json, v4_rows.json) are
// derived under (table profiles).
type Profile struct {
	_       struct{} `stash:"context=profiles"`
	ID      int64    `stash:"id,passthrough"`
	Visits  int32    `stash:"visits,encrypt_into=Integer"`
	Balance int64    `stash:"balance,encrypt_into=Bigint"`
	Active  bool     `stash:"active,encrypt_into=Boolean"`
	Ratio   float32  `stash:"ratio,encrypt_into=Real"`
	Score   float64  `stash:"score,encrypt_into=Double"`
	Note    string   `stash:"note,encrypt_into=Text"`
	Name    string   `stash:"name,encrypt_into=TextMatch"`
}
