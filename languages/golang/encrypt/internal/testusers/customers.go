package testusers

import "encoding/json"

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Customer -name Customer

// Customer holds two encrypted JSON documents (the EQL type JsonSearch,
// stored in public.eql_v4_json_search): a profile whose $.age and every
// visit's $.at order, and optional preferences, stored as SQL NULL when nil.
type Customer struct {
	_       struct{}         `stash:"context=customers"`
	ID      int64            `stash:"id,passthrough"`
	Profile json.RawMessage  `stash:"profile,encrypt_into=JsonSearch(ordered=$.age;$.visits[*].at)"`
	Prefs   *json.RawMessage `stash:"prefs,encrypt_into=JsonSearch,null=sql"`
}
