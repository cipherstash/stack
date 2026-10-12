package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Profile -name Profile

// Profile stores one field in each EQL v4 type the engine produces besides
// TextEq, the shape the cross-language fixture
// packages/eql/tests/encryption/fixtures/v4_queries.json is derived under
// (table profiles).
type Profile struct {
	_       struct{} `stash:"context=profiles"`
	ID      int64    `stash:"id,passthrough"`
	Age     int32    `stash:"age,encrypt_into=IntegerEq"`
	Visits  int32    `stash:"visits,encrypt_into=Integer"`
	Balance int64    `stash:"balance,encrypt_into=BigintEq"`
	Active  bool     `stash:"active,encrypt_into=Boolean"`
	Ratio   float32  `stash:"ratio,encrypt_into=Real"`
	Score   float64  `stash:"score,encrypt_into=Double"`
	Note    string   `stash:"note,encrypt_into=Text"`
	Name    string   `stash:"name,encrypt_into=TextMatch"`
}
