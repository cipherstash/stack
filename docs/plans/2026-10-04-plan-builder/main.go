package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"example.com/app/blocklist"
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

	const tenant = "tenant-42"
	cipher := client.Keyset(stackencrypt.KeysetName(tenant))
	store := users.NewSQLStore(db, client)

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

	if err := store.Create(ctx, tenant, alice); err != nil {
		return err
	}
	if err := store.Import(ctx, tenant, newHires); err != nil {
		return err
	}

	bobs, err := store.FindByEmail(ctx, tenant, "bob@example.com")
	if err != nil {
		return err
	}
	admins, err := store.WithRole(ctx, tenant, "admin")
	if err != nil {
		return err
	}
	adults, err := store.OldestFirst(ctx, tenant, 18)
	if err != nil {
		return err
	}
	if _, err := users.RoundTripForTenant(ctx, cipher, "tenant-42-region-ap", alice); err != nil {
		return err
	}

	blocked := blocklist.New(db, cipher)
	if err := blocked.Block(ctx, "spam@example.net"); err != nil {
		return err
	}
	isBlocked, err := blocked.Blocked(ctx, "spam@example.net")
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
	fmt.Println("bob:", ids(bobs), "admins:", ids(admins), "adults, oldest first:", ids(adults), "blocked:", isBlocked)
	return nil
}

func ids(people []users.User) []int64 {
	out := make([]int64, len(people))
	for i, p := range people {
		out[i] = p.ID
	}
	return out
}
