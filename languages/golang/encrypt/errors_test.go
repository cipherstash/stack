package encrypt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Each kind the engine refuses through the public API is its sentinel for
// errors.Is and a Diagnostic for errors.As. The ZeroKMS kinds are in
// TestTransportOutcomesMapToErrors, and the guest's own refusals in
// TestGuestRefusalsCarryTheirDiagnostic.
func TestEachKindCarriesItsDiagnostic(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	elsewhere, err := testusers.Encrypt(ctx, c.Keyset(encrypt.KeysetName("tenant-b")), people[:1])
	if err != nil {
		t.Fatal(err)
	}
	flipped, err := testusers.Encrypt(ctx, cipher, people[:1])
	if err != nil {
		t.Fatal(err)
	}
	flipped[0].Email.Ciphertext[len(flipped[0].Email.Ciphertext)-1] ^= 1
	truncated, err := testusers.Encrypt(ctx, cipher, people[:1])
	if err != nil {
		t.Fatal(err)
	}
	truncated[0].Email.Ciphertext = truncated[0].Email.Ciphertext[:3]
	cases := []struct {
		name string
		run  func() error
		want error
		code string
	}{
		{"a row sealed under another keyset", func() error {
			_, err := testusers.Decrypt(ctx, cipher, elsewhere)
			return err
		}, encrypt.ErrForeignKeyset, "stack_encrypt::foreign_keyset"},
		{"a tampered leaf", func() error {
			_, err := testusers.Decrypt(ctx, cipher, flipped)
			return err
		}, encrypt.ErrAuthentication, "stack_encrypt::aead"},
		{"match text with no token", func() error {
			_, err := testusers.Fields.Email.Matches(ctx, cipher, "")
			return err
		}, encrypt.ErrTerm, "stack_encrypt::empty_term_text"},
		{"a ciphertext that is not a sealed value", func() error {
			_, err := testusers.Decrypt(ctx, cipher, truncated)
			return err
		}, encrypt.ErrEncoding, "stack_encrypt::leaf_truncated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			encrypt.WantCode(t, err, tc.code)
		})
	}
}

// A foreign-keyset refusal names both keysets: the one the cipher is bound
// to and the one the row was sealed under.
func TestAForeignKeysetNamesBothKeysets(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	other := c.Keyset(encrypt.KeysetName("tenant-b"))
	encrypted, err := testusers.Encrypt(ctx, other, people[:1])
	if err != nil {
		t.Fatal(err)
	}
	_, err = testusers.Decrypt(ctx, c.DefaultKeyset(), encrypted)
	d := encrypt.WantDiagnostic(t, err, "stack_encrypt::foreign_keyset")
	wantExpected, err := c.DefaultKeyset().KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantFound, err := other.KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := d.ExpectedKeyset(); !ok || got != wantExpected {
		t.Errorf("ExpectedKeyset() = %x, %v; want %s", got, ok, wantExpected)
	}
	if got, ok := d.FoundKeyset(); !ok || got != wantFound {
		t.Errorf("FoundKeyset() = %x, %v; want %s", got, ok, wantFound)
	}
	if d.Help == "" {
		t.Error("a foreign keyset gives no help")
	}
}

// A keyset name that breaks a naming rule is ErrEncoding, with the guest's
// malformed-input code. Its message names the rule the name broke, and its
// Help states the rules. The name is checked where a cipher first uses it,
// on a KeysetID and on an encrypt alike.
func TestAnInvalidKeysetNameNamesTheRule(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cases := []struct {
		name    string
		keyset  encrypt.KeysetName
		message []string
	}{
		{"a space", "tenant 42", []string{`"tenant 42"`, `' '`}},
		{"a dot", "tenant.42", []string{`"tenant.42"`, `'.'`}},
		{"a letter outside ASCII", "ténant", []string{`"ténant"`, `'é'`}},
		{"no characters", "", []string{"empty"}},
		{"65 characters", encrypt.KeysetName(strings.Repeat("a", 65)), []string{"65 characters", "64"}},
	}
	for _, tc := range cases {
		cipher := c.Keyset(tc.keyset)
		calls := map[string]func() error{
			"KeysetID": func() error { _, err := cipher.KeysetID(ctx); return err },
			"Encrypt":  func() error { _, err := testusers.Encrypt(ctx, cipher, people[:1]); return err },
		}
		for call, run := range calls {
			t.Run(tc.name+"/"+call, func(t *testing.T) {
				err := run()
				if !errors.Is(err, encrypt.ErrEncoding) {
					t.Fatalf("err = %v, want ErrEncoding", err)
				}
				d := encrypt.WantDiagnostic(t, err, "stack_guest_abi::malformed_input")
				for _, want := range tc.message {
					if !strings.Contains(d.Message, want) {
						t.Errorf("Message = %q, want it to contain %q", d.Message, want)
					}
				}
				for _, want := range []string{"1 to 64 characters", "A to Z and a to z", "0 to 9", "_, -, and /"} {
					if !strings.Contains(d.Help, want) {
						t.Errorf("Help = %q, want it to contain %q", d.Help, want)
					}
				}
			})
		}
	}
}
