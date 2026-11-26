package encrypt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// A data key ZeroKMS refuses is ErrForbidden with the code
// stack_kms::retrieve_key_failed, whatever the cause. The Help says which
// cause is likely where the call knows: a cipher loaded its keyset first, so
// for a cipher the context is the likely cause; the Client did not, so its
// Help names every cause. Neither names a scope's value.
func TestARefusedDataKeySaysWhichCause(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.Keyset(encrypt.KeysetName("tenant-a"))
	rows, err := testusers.Encrypt(ctx, cipher.Scope("scope-value-7"), people[:1])
	if err != nil {
		t.Fatal(err)
	}
	defaultRows, err := testusers.Encrypt(ctx, c.DefaultKeyset().Scope("scope-value-7"), people[:1])
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		rows []testusers.EncryptedUser
		with encrypt.Decrypter
		want []string
	}{
		{
			name: "a cipher with another scope",
			with: cipher.Scope("scope-value-8"),
			want: []string{`keyset "tenant-a"`, "1 scope part and no binding parts", "Cipher.Scope", "Cipher.Bind", "context field", "disabled since it was loaded"},
		},
		{
			name: "a cipher with no scope",
			with: cipher,
			want: []string{`keyset "tenant-a"`, "no scope parts and no binding parts", "Cipher.Scope"},
		},
		{
			name: "a cipher with a binding",
			with: cipher.Scope("scope-value-7").Bind(int64(1)),
			want: []string{"1 scope part and 1 binding part", "Cipher.Bind"},
		},
		{
			name: "the default keyset's cipher",
			rows: defaultRows,
			with: c.DefaultKeyset().Scope("scope-value-7", "scope-value-8"),
			want: []string{"the client's default keyset", "2 scope parts"},
		},
		{
			name: "the Client",
			with: c,
			want: []string{"keyset the value was sealed under is disabled", "scope to retrieve keys", "Cipher.Scope", "Cipher.Bind", "context field", "ErrNotFound"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealed := rows
			if tc.rows != nil {
				sealed = tc.rows
			}
			_, err := testusers.Decrypt(ctx, tc.with, sealed)
			if !errors.Is(err, encrypt.ErrForbidden) {
				t.Fatalf("Decrypt: %v, want ErrForbidden", err)
			}
			var d *encrypt.Diagnostic
			if !errors.As(err, &d) {
				t.Fatalf("Decrypt: %v, want a Diagnostic", err)
			}
			if d.Code != "stack_kms::retrieve_key_failed" {
				t.Errorf("Code = %q, want stack_kms::retrieve_key_failed", d.Code)
			}
			for _, want := range tc.want {
				if !strings.Contains(d.Help, want) {
					t.Errorf("Help = %q, want it to contain %q", d.Help, want)
				}
			}
			if strings.Contains(d.Help, "scope-value") || strings.Contains(err.Error(), "scope-value") {
				t.Errorf("a scope's value is in the error: %v; Help %q", err, d.Help)
			}
		})
	}
}

// A cipher's own Help is given only to a refused data key: other failures
// keep the Help the guest gave them.
func TestOnlyARefusedDataKeyGetsTheCipherHelp(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.Keyset(encrypt.KeysetName("tenant-a"))
	rows, err := testusers.Encrypt(ctx, cipher, people[:1])
	if err != nil {
		t.Fatal(err)
	}
	_, err = testusers.Decrypt(ctx, c.Keyset(encrypt.KeysetName("tenant-b")), rows)
	if !errors.Is(err, encrypt.ErrForeignKeyset) {
		t.Fatalf("Decrypt: %v, want ErrForeignKeyset", err)
	}
	var d *encrypt.Diagnostic
	if errors.As(err, &d) && strings.Contains(d.Help, "scope part") {
		t.Errorf("a foreign keyset got the refusal's Help: %q", d.Help)
	}
}
