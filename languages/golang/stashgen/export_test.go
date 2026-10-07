package stashgen

import (
	"context"
	"io"

	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
)

// GenerateFor is generateFor for the external tests, which name the message's
// type instead of holding a value of it: the type lives in a module the test
// process cannot import.
func GenerateFor(ctx context.Context, engine Engine, notices io.Writer, output string, source policy.Source, message policy.Message, pkgPath, typeName string) error {
	return generateFor(ctx, generateConfig{output: output, engine: engine, notices: notices}, source, message, pkgPath, typeName)
}

// MessageType is messageType for the external tests.
var MessageType = messageType
