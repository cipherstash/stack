package stashgen

import (
	"context"
	"io"

	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// GenerateFor is generateFor for the external tests, which name the message's
// type instead of holding a value of it: the type lives in a module the test
// process cannot import.
func GenerateFor(ctx context.Context, engine Engine, notices io.Writer, output string, source policy.Source, message policy.Message, pkgPath, typeName string) error {
	return GenerateForNamed(ctx, engine, notices, output, "", source, message, pkgPath, typeName)
}

// GenerateForNamed is GenerateFor with WithName.
func GenerateForNamed(ctx context.Context, engine Engine, notices io.Writer, output, name string, source policy.Source, message policy.Message, pkgPath, typeName string) error {
	return generateFor(ctx, generateConfig{output: output, name: name, engine: engine, notices: notices}, source, message, pkgPath, typeName)
}

// MessageType is messageType for the external tests.
var MessageType = messageType

// DocumentType is an EQL type that holds a JSON document, for an external
// test's engine: its plaintext kind is the engine's json, which only this
// package can set. query is the type's query type, "" for a storage-only
// type.
func DocumentType(name, query string) EQLType {
	return EQLType{Name: name, Plaintext: KindJSON, Query: query, Producible: true, wire: record.JSON}
}
