package encrypt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// An error never contains the values of an encryption context (the
// Diagnostic doc comment and the README's "Errors" section say so). Each
// case below raises an error from a context value that holds a marker, and
// checks that the error keeps its kind and leaves the marker out.

func TestErrorsLeaveOutContextValues(t *testing.T) {
	c := contextFixtureClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	tests := []struct {
		name    string
		kind    error
		markers []string
		call    func() error
	}{
		{
			name:    "a row whose context field differs from the cipher's context",
			kind:    encrypt.ErrContextMismatch,
			markers: []string{"marker-row", "marker-cipher"},
			call: func() error {
				row := []testusers.Note{{Tenant: "tenants/marker-row", Text: "hello", ID: 1}}
				_, err := testusers.EncryptNote(ctx, cipher.Context("tenants/marker-cipher"), row)
				return err
			},
		},
		{
			name:    "a cipher context for a type with a context tag",
			kind:    encrypt.ErrEncoding,
			markers: []string{"marker-cipher"},
			call: func() error {
				_, err := testusers.EncryptLiteralNote(ctx, cipher.Context("tenants/marker-cipher"), []testusers.LiteralNote{{Text: "hello"}})
				return err
			},
		},
		{
			name:    "a cipher context that is not a plain label",
			kind:    encrypt.ErrEncoding,
			markers: []string{"marker-cipher"},
			call: func() error {
				row := []testusers.Note{{Tenant: "tenants/marker-cipher(", Text: "hello", ID: 1}}
				_, err := testusers.EncryptNote(ctx, cipher.Context("tenants/marker-cipher("), row)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if !errors.Is(err, tt.kind) {
				t.Fatalf("got %v, want %v", err, tt.kind)
			}
			for _, marker := range tt.markers {
				if strings.Contains(err.Error(), marker) {
					t.Errorf("the error contains the context value %q: %v", marker, err)
				}
			}
		})
	}
}
