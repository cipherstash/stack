package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Tally -name Tally

// Tally stores the smallint EQL v4 types, under Profile's table so its
// query shares v4_queries.json (key tally). It is a model of its own
// because Profile's rows are frozen in stored_v4_rows_v1.json: a new
// Profile field would change what those rows store.
type Tally struct {
	_     struct{} `stash:"context=profiles"`
	ID    int64    `stash:"id,passthrough"`
	Small int16    `stash:"small,encrypt_into=Smallint"`
	Count int16    `stash:"tally,encrypt_into=SmallintEq"`
	Wide  int32    `stash:"wide,encrypt_into=SmallintEq"`
}
