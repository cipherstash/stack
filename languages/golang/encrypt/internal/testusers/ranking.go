package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Ranking -name Ranking

// Ranking stores one field in each OPE-ordered EQL v4 type the engine
// produces, the shape the ordered cross-language fixtures under
// packages/eql/tests/encryption/fixtures (v4_ordered_queries.json,
// v4_ordered_rows.json) are derived under (table rankings). The `Ord` and
// `OrdOpe` types of a family store the same terms; each gets a column so
// both plans run.
type Ranking struct {
	_      struct{} `stash:"context=rankings"`
	ID     int64    `stash:"id,passthrough"`
	Level  int32    `stash:"level,encrypt_into=IntegerOrd"`
	Floor  int32    `stash:"floor,encrypt_into=IntegerOrdOpe"`
	Points int64    `stash:"points,encrypt_into=BigintOrd"`
	Total  int64    `stash:"total,encrypt_into=BigintOrdOpe"`
	Speed  float32  `stash:"speed,encrypt_into=RealOrd"`
	Pace   float32  `stash:"pace,encrypt_into=RealOrdOpe"`
	Score  float64  `stash:"score,encrypt_into=DoubleOrd"`
	Mean   float64  `stash:"mean,encrypt_into=DoubleOrdOpe"`
	Title  string   `stash:"title,encrypt_into=TextOrd"`
	Handle string   `stash:"handle,encrypt_into=TextOrdOpe"`
}
