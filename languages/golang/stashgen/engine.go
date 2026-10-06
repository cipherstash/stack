package stashgen

import (
	"context"
	"errors"
)

// Engine answers the generator's questions about what the Rust engine can do.
// The generator holds no copy of the engine's rules: every refusal about an
// index, an EQL type or a field type comes from here.
//
// The SDK's implementation runs the WASI guest that the SDK embeds. See
// [GuestEngine].
type Engine interface {
	// EQLTypes lists the EQL types the engine can produce: each name, its
	// plaintext kind, its indexes and its query type.
	EQLTypes(ctx context.Context) ([]EQLType, error)
	// Check refuses a declaration the engine cannot run: an index or an EQL
	// type that does not apply to a field's Go type, a field type it cannot
	// seal, an EQL type it cannot produce, or an index option it cannot
	// carry. The error names the field.
	Check(ctx context.Context, d Declaration) error
}

// EQLType is one EQL type the engine produces, such as TextEq.
type EQLType struct {
	// Name is the Go type name in encrypt/eql, and the value of encrypt_into.
	Name string
	// Plaintext is the kind of Go value the type seals.
	Plaintext Kind
	// Indexes are the terms the type carries.
	Indexes []IndexName
	// Query is the Go type name of the type's query value, such as
	// TextEqQuery, or "" for a type with no terms.
	Query string
}

// ErrEngineUnavailable is returned by [GuestEngine] until the SDK's guest
// is wired to the generator.
var ErrEngineUnavailable = errors.New("stashgen: the embedded engine is not available in this build")

// GuestEngine returns the engine the SDK embeds.
//
// TODO(stack#1046 integration): run the WASI guest that package encrypt
// embeds (the build with the EQL types), ask it for its EQL types and have
// it check each declaration. Until then this returns [ErrEngineUnavailable],
// and stashgen stops before it reads any package. The fake in
// internal/fakeengine is the reference for what an Engine answers.
func GuestEngine(context.Context) (Engine, error) {
	return nil, ErrEngineUnavailable
}
