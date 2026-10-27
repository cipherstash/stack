// Command json demonstrates a typed encrypted JSON document in PostgreSQL.
// Run go generate after changing Customer or its stash tags.
package main

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Customer -redact

// Visit is one visit stored inside a customer's encrypted profile.
type Visit struct {
	At int64 `json:"at"`
}

// Profile is a typed JSON document. Its Age is searchable by order.
type Profile struct {
	Name   string  `json:"name"`
	Age    int64   `json:"age"`
	Visits []Visit `json:"visits"`
}

// Customer stores Profile in one EQL v4 JSON column.
type Customer struct {
	_       struct{} `stash:"context=customers"`
	ID      int64    `stash:"id,passthrough"`
	Profile Profile  `stash:"profile,encrypt_into=JsonSearch(ordered=$.age)"`
}
