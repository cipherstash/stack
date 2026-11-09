package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
)

// The generated record's contexts are pinned, so a change to the
// declaration that moves a field's context fails this test. The text is the
// same as the Rust record derive prints for an `EncryptedUser` with the same
// fields.
func TestUserContextsArePinned(t *testing.T) {
	if _, err := encrypttest.Contexts(context.Background(), declaration); errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	encrypttest.AssertContexts(t, declaration,
		"email\n  context: users / email\n"+
			"age\n  context: users / age\n")
}
