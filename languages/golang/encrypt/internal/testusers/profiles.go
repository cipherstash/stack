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
	Age     int32    `stash:"age,encrypt_into=IntegerEq"`
	Rank    int64    `stash:"rank,encrypt_into=BigintEq"`
	Weight  float32  `stash:"weight,encrypt_into=RealEq"`
	Price   float64  `stash:"price,encrypt_into=DoubleEq"`
}

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Widened -name Widened

// Widened stores Go integers of other widths in Profile's integer EQL types,
// under the same table and columns (ADR-0002): narrower ones that always
// fit, and a wider one gensupport range checks value by value. Its terms are
// the ones Profile's int32 and int64 fields store for the same values.
type Widened struct {
	_       struct{} `stash:"context=profiles"`
	Visits  uint8    `stash:"visits,encrypt_into=Integer"`
	Balance int      `stash:"balance,encrypt_into=Bigint"`
	Age     int16    `stash:"age,encrypt_into=IntegerEq"`
	Rank    uint32   `stash:"rank,encrypt_into=BigintEq"`
	Count   int64    `stash:"count,encrypt_into=IntegerEq"`
}
