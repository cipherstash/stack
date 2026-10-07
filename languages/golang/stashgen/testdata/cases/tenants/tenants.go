// Package tenants declares a struct whose context is one of its own fields:
// the `context_field` tag, in place of a `_ struct{}` context field.
package tenants

import "github.com/cipherstash/stack/languages/golang/encrypt"

//go:generate go tool stashgen -type Note -model Rows=NoteRow

// Note is sealed under the context its Tenant field names, so a row stored
// under "tenants/acme" opens only as acme's, and a query names the tenant.
type Note struct {
	Tenant string `stash:"tenant,context_field" db:"tenant"`
	Text   string `stash:"text,encrypt,index=equality;match" db:"text"`
	ID     int64  `stash:"id,passthrough" db:"id"`
}

// NoteRow is a model for Note in separate columns: the context field is a
// column like a passthrough field.
type NoteRow struct {
	Tenant    string               `stash:"tenant"`
	Text      encrypt.Ciphertext   `stash:"text"`
	TextEq    encrypt.EqualityTerm `stash:"text,equality"`
	TextMatch encrypt.MatchTerm    `stash:"text,match"`
	ID        int64                `stash:"id"`
}
