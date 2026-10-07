// Package eql holds the EQL types a program stores: one Go type per EQL
// type, each holding the EQL value as the JSON bytes PostgreSQL stores in
// the type's domain, and the query types that match them.
//
// A field with `stash:"email,encrypt_into=TextEq"` is an [TextEq] in the
// generated encrypted type, and its Fields entry's Query returns a
// [TextEqQuery]. The guest builds every value: generated code stores what
// the guest returns and never assembles an EQL value itself (ADR-0007,
// amended 2026-10-06). Each type implements driver.Valuer and sql.Scanner
// for one column, and json.Marshaler, which writes the value as the JSON
// it is.
//
// Importing this package links the build of the engine that holds the EQL
// types: eql_gen.go's init registers the embedded module with package
// encrypt, and that registration cannot fail. A generated file that names
// an EQL type imports this package, so a program with EQL types runs the
// build that has them and a program without runs the smaller one.
//
// The types and the [Types] table are generated from the EQL catalog by
// eql-codegen (`mise run types:generate` in packages/eql); eql_gen.go is
// committed and drift-gated. The engine produces [TextEq] today; every
// other type is listed with the reason it cannot be produced yet, and
// stashgen refuses it.
package eql

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

// Type is one EQL type as the catalog describes it: what stashgen learns
// from the engine's se_targets export, in Go. Name is the engine's name,
// the value of encrypt_into; GoName is the type's name in this package.
type Type struct {
	// Name is the type's name across languages, and the engine's: TextEq.
	Name string
	// GoName is the type's name in this package: Name, save the JSON family
	// (Json is JSON).
	GoName string
	// Family is the catalog family: text.
	Family string
	// Suffix is the query-capability suffix: Eq; empty for a storage-only
	// type.
	Suffix string
	// Plaintext is the wire kind the type is produced from (string, ...),
	// or "" while unspecified.
	Plaintext string
	// SQLDomain is the stored value's PostgreSQL domain.
	SQLDomain string
	// Indexes are the indexes the type carries: eq, match, ore, ope, json.
	Indexes []string
	// Query is the query type's engine name, or "" for a storage-only type.
	Query string
	// QuerySQLDomain is the query type's PostgreSQL domain, or "".
	QuerySQLDomain string
	// Producible says whether the engine produces the type today.
	Producible bool
	// Reason says why not, when it does not.
	Reason string
}

// Lookup finds the type the engine names, or false.
func Lookup(name string) (Type, bool) {
	for _, t := range Types {
		if t.Name == name {
			return t, true
		}
	}
	return Type{}, false
}

// errNull is a NULL scanned into an EQL type.
var errNull = errors.New("eql: cannot scan NULL into an EQL value")

// value is an EQL value as the driver takes it: the JSON text, or NULL for
// an empty value.
func value(b []byte) (driver.Value, error) {
	if b == nil {
		return nil, nil
	}
	return string(b), nil
}

// scan reads a column into an EQL value: jsonb comes back as bytes or text.
func scan(dst *[]byte, src any, kind string) error {
	switch v := src.(type) {
	case []byte:
		out := make([]byte, len(v))
		copy(out, v)
		*dst = out
		return nil
	case string:
		*dst = []byte(v)
		return nil
	case nil:
		return fmt.Errorf("%w: %s", errNull, kind)
	default:
		return fmt.Errorf("eql: cannot scan %T into %s", src, kind)
	}
}

// marshal is the EQL value as JSON: the bytes it is, null when empty.
func marshal(b []byte, kind string) ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("eql: %s holds bytes that are not JSON", kind)
	}
	return b, nil
}

// unmarshal reads an EQL value from JSON: the document as it is.
func unmarshal(dst *[]byte, b []byte) error {
	if string(b) == "null" {
		*dst = nil
		return nil
	}
	*dst = append([]byte(nil), b...)
	return nil
}
