package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"example.com/app/contacts"
	"example.com/app/crm"
	"example.com/app/documents"
	"example.com/app/users"
	"github.com/cipherstash/stack/languages/golang/stackencrypt"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	client, err := stackencrypt.NewClient(ctx, stackencrypt.WithCredentials(stackencrypt.AutoCredentials()))
	if err != nil {
		return err
	}
	defer client.Close()

	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()

	// One cipher for each tenant: its keyset, and its part of every field's
	// context. Every call through this cipher carries both.
	cipher := client.Keyset(stackencrypt.KeysetName("tenant-42")).Extend("tenant-42")
	store := users.NewSQLStore(db)

	alice := users.User{
		ID:       1,
		Email:    "alice@example.com",
		Age:      34,
		Attrs:    map[string]any{"role": "admin", "team": "payments"},
		Notes:    "Prefers email.",
		Internal: "never stored",
	}
	newHires := []users.User{
		{ID: 2, Email: "bob@example.com", Age: 17, Attrs: map[string]any{"role": "intern"}, Notes: "Starts Monday."},
		{ID: 3, Email: "carol@example.com", Age: 52, Attrs: map[string]any{"role": "admin"}},
	}

	if err := store.Create(ctx, cipher, alice); err != nil {
		return err
	}
	if err := store.Import(ctx, cipher, newHires); err != nil {
		return err
	}

	bobs, err := store.FindByEmail(ctx, cipher, "bob@example.com")
	if err != nil {
		return err
	}
	admins, err := store.WithRole(ctx, cipher, "admin")
	if err != nil {
		return err
	}
	adults, err := store.AtLeast(ctx, cipher, 18)
	if err != nil {
		return err
	}

	// Two types in one ZeroKMS request.
	list := []crm.Contact{{ID: 9, Email: "dan@example.com", PhoneNumber: "+61 400 000 000"}}
	encryptedUsers, encryptedContacts, err := stackencrypt.Batch2(ctx, cipher,
		users.Encryption(newHires), contacts.Encryption(list))
	if err != nil {
		return err
	}

	handbook := documents.Document{Title: "Handbook", Body: "Welcome aboard.", Tags: []string{"hr"}}
	if err := documents.Save(ctx, db, cipher, 100, handbook); err != nil {
		return err
	}
	if _, err := documents.Load(ctx, db, client, 100); err != nil {
		return err
	}

	// Print ids and counts only. Every other value here is plaintext.
	fmt.Println("bob:", ids(bobs), "admins:", ids(admins), "adults:", ids(adults),
		"batched:", len(encryptedUsers), len(encryptedContacts))
	return nil
}

func ids(people []users.User) []int64 {
	out := make([]int64, len(people))
	for i, p := range people {
		out[i] = p.ID
	}
	return out
}
