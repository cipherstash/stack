package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
)

// The generated record's contexts are pinned, field by field, so a change
// to the declaration that moves a field's context fails this test. The
// parts are the ones a Rust test states for an `EncryptedUser` with the
// same fields.
func TestUserContextsArePinned(t *testing.T) {
	if _, err := encrypttest.Contexts(context.Background(), declaration); errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	encrypttest.AssertContexts(t, declaration,
		encrypttest.Field("email", "users", "email"),
		encrypttest.Field("age", "users", "age"),
	)
}
