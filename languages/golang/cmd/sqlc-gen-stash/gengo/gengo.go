// Package gengo exposes what sqlc-gen-go works out for a package, which
// sqlc-gen-go keeps internal: its parsed options, the enums, structs and
// queries it builds, the imports its files use and the files its templates
// write. A plugin that writes code beside sqlc-gen-go's package reads the Go
// names from here instead of parsing the files.
//
// The types are sqlc-gen-go's own, from a copy of the version the tool line
// in sqlc-gen-stash's go.mod pins, so they change when that pin moves.
package gengo

import (
	"bytes"
	"encoding/json"

	"github.com/sqlc-dev/plugin-sdk-go/plugin"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/internal/golang"
	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/internal/golang/opts"
)

type (
	// Package is what sqlc-gen-go works out for a package, and the files it
	// writes.
	Package = golang.Package
	// Struct is a struct sqlc-gen-go declares: a table's model, or a
	// query's parameters or row.
	Struct = golang.Struct
	// Declared is a Struct the package declares, and the file it declares
	// it in.
	Declared = golang.Declared
	// Field is a field of a Struct, with the catalog column it holds.
	Field = golang.Field
	// Query is a query of the package, with its parameters and its row.
	Query = golang.Query
	// QueryValue is a query's parameters or row.
	QueryValue = golang.QueryValue
	// Enum is an enum type sqlc-gen-go declares.
	Enum = golang.Enum
	// Options are a codegen entry's sqlc-gen-go options, as sqlc's own
	// gen.go block takes them.
	Options = opts.Options
	// GlobalOptions are sqlc-gen-go's options for every codegen entry, as
	// sqlc's own top-level overrides.go block takes them.
	GlobalOptions = opts.GlobalOptions
	// Override is an entry of Options.Overrides or GlobalOptions.Overrides.
	Override = opts.Override
)

// Build runs sqlc-gen-go on req, whose plugin and global options are
// sqlc-gen-go's, and returns what it works out and the files it writes.
func Build(req *plugin.GenerateRequest) (*Package, error) {
	return golang.Build(req)
}

// ModelsFile is the name of the file sqlc-gen-go writes the package's models
// to.
func ModelsFile(o *Options) string {
	return golang.ModelsFile(o)
}

// DecodeOptions decodes a codegen entry's sqlc-gen-go options, as sqlc's own
// gen.go block holds them, refusing an option sqlc-gen-go doesn't know,
// which sqlc-gen-go itself ignores. raw may be empty.
func DecodeOptions(raw []byte) (*Options, error) {
	var o Options

	return &o, decodeStrict(raw, &o)
}

// DecodeGlobalOptions decodes sqlc-gen-go's options for every codegen entry,
// refusing an option sqlc-gen-go doesn't know. raw may be empty.
func DecodeGlobalOptions(raw []byte) (*GlobalOptions, error) {
	var o GlobalOptions

	return &o, decodeStrict(raw, &o)
}

func decodeStrict(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	return dec.Decode(v)
}
