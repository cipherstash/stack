package main

import (
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
)

// The generated record's contexts are pinned, field by field, so a change
// to the declaration that moves a field's context fails this test. The
// parts are the ones a Rust test states for an `EncryptedUser` with the
// same fields.
func TestUserContextsArePinned(t *testing.T) {
	encrypttest.AssertContexts(t, declaration,
		encrypttest.Field("email", "users", "email"),
		encrypttest.Field("age", "users", "age"),
	)
}
