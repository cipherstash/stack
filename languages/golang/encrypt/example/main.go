package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// No options: the credentials come from AutoCredentials, which is the
	// environment first (CS_CLIENT_ACCESS_KEY + CS_WORKSPACE_CRN, CS_CLIENT_ID
	// + CS_CLIENT_KEY), then the developer profile `stash auth login` writes.
	client, err := encrypt.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("connecting to ZeroKMS: %w", err)
	}
	defer client.Close()
	fmt.Printf("connected (%v)\n", client)

	// One cipher for one tenant: the default keyset, and the tenant as a
	// part of every field's context. Every call through it carries both.
	cipher := client.DefaultKeyset().Extend("tenant-42")

	people := []User{
		{ID: 1, Email: "alice@example.com", Age: 34},
		{ID: 2, Email: "bob@example.com", Age: 29},
	}

	// One call, one ZeroKMS request for both rows.
	encrypted, err := Encrypt(ctx, cipher, people)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	for _, e := range encrypted {
		// EncryptedUser prints its passthrough fields and hides the rest.
		fmt.Printf("stored: %v (ciphertext %d bytes, equality %d bytes, match %d positions)\n",
			e, len(e.Email.Ciphertext), len(e.Email.Equality), len(e.Email.Match)/2)
	}

	// A query term for one field compares against the stored terms.
	term, err := Fields.Email.Equality(ctx, cipher, "bob@example.com")
	if err != nil {
		return fmt.Errorf("query term: %w", err)
	}
	for _, e := range encrypted {
		fmt.Printf("id %d matches bob@example.com: %v\n", e.ID, term.Equal(e.Email.Equality))
	}

	// Decrypt through the cipher. It carries the extension that Encrypt
	// used, and it refuses rows from another keyset. The client would refuse
	// these rows: it opens only rows sealed with no extension.
	back, err := Decrypt(ctx, cipher, encrypted)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	// Print ids only: everything else here is plaintext.
	for _, u := range back {
		fmt.Printf("decrypted id %d\n", u.ID)
	}
	return nil
}
