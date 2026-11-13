package testusers

import "encoding/json"

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type Setting -name Setting

// Setting holds encrypted JSON documents with no index (the EQL type Json,
// stored in public.eql_v4_json): each is one ciphertext, stored and read
// back whole, and nothing inside it is queried. Its raw document is JSON
// text, its preferences are a Go type and are SQL NULL when nil, and its
// labels are a map.
//
// Setting's rows are frozen in stored_v4_json_rows_v1.json, which is never
// regenerated: a change to a field here changes what those rows store.
// Put a new case in a model of its own.
type Setting struct {
	_      struct{}          `stash:"context=settings"`
	ID     int64             `stash:"id,passthrough"`
	Raw    json.RawMessage   `stash:"raw,encrypt_into=Json"`
	Prefs  *SettingPrefs     `stash:"prefs,encrypt_into=Json,null=sql"`
	Labels map[string]string `stash:"labels,encrypt_into=Json"`
}

// SettingPrefs is a setting's optional preferences document.
type SettingPrefs struct {
	Theme string `json:"theme"`
	Beta  bool   `json:"beta"`
}
