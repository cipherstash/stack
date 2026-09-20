// Command example exercises the stack-encrypt Go binding against real
// ZeroKMS, using the credentials `stash auth login` leaves in the developer
// profile.
//
//	stash auth login
//	mise run wasm:guest:build          # the embedded guest must be current
//	go run ./example
//
// It walks the four things the binding does — seal a value, seal a record
// with its index terms, probe those terms with a query, and open both again
// — and prints what crossed the boundary at each step.
package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// A record type. The `stash` tag is the Go stand-in for Rust's
// `#[derive(EncryptFrom)]`: `context=` is the field's own encryption
// context, `index=` the terms to derive beside the ciphertext.
type user struct {
	ID    int64  `stash:"-"`
	Email string `stash:"context=users/email,index=eq;match"`
	Age   uint32 `stash:"context=users/age,index=eq;ore"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	creds, err := loadCredentials()
	if err != nil {
		return err
	}
	fmt.Printf("workspace %s (%s)\n", creds.Workspace, creds.describe())

	ctx := context.Background()
	client, err := stackencrypt.NewClient(ctx, stackencrypt.Config{
		ClientID:  creds.ClientID,
		ClientKey: creds.ClientKey,
		// Asked on every request, so the client follows the profile
		// rather than pinning one token; see profile.go.
		Token: creds.token(),
		// ZeroKMSURL is left empty: the endpoint is resolved from the
		// token's services claim on first use.
	})
	if err != nil {
		return fmt.Errorf("connecting to ZeroKMS: %w", err)
	}
	// Close runs the guest's own wipe of the client key and every loaded
	// index key. The memory's protection does not wait on it (see the
	// package docs); this is ordinary resource hygiene.
	defer client.Close()

	cipher := client.DefaultKeyset()
	keysetID, err := cipher.KeysetID(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("default keyset %s\n\n", keysetID)

	if err := values(ctx, cipher); err != nil {
		return err
	}
	records, err := recordsAndTerms(ctx, cipher)
	if err != nil {
		return err
	}
	return ordering(records)
}

// A whole value, sealed under an AAD of the caller's choosing. The shape of
// the ciphertext mirrors the plaintext, and a field marked Plain rides
// alongside it in the clear.
func values(ctx context.Context, cipher *stackencrypt.Cipher) error {
	section("a value")

	aad := []byte("users/v1")
	in := map[string]any{
		"name": "alice",
		"age":  uint32(34),
		"note": vcvalue.Plain{V: "not secret"},
	}
	fmt.Printf("  plaintext   %v\n", in)

	sealed, err := cipher.Encrypt(ctx, in, aad)
	if err != nil {
		return fmt.Errorf("encrypting a value: %w", err)
	}
	for name, node := range sealed.(map[string]any) {
		if leaf, ok := node.(stackencrypt.Sealed); ok {
			fmt.Printf("  %-11s %d bytes of ciphertext\n", name, len(leaf))
		} else {
			fmt.Printf("  %-11s %v (passthrough — in the clear, and unauthenticated)\n", name, node)
		}
	}

	opened, err := cipher.Decrypt(ctx, sealed, aad)
	if err != nil {
		return fmt.Errorf("decrypting a value: %w", err)
	}
	fmt.Printf("  opened      %v\n", opened)

	// The AAD is bound into the key as well as the ciphertext, so the wrong
	// one does not open the value — it is refused, not silently wrong.
	if _, err := cipher.Decrypt(ctx, sealed, []byte("some other context")); err == nil {
		return fmt.Errorf("a value opened under an AAD it was not sealed under")
	} else {
		fmt.Printf("  wrong AAD   refused: %v\n", err)
	}
	return nil
}

// A record: every field sealed under its own context, with the index terms
// its tag asked for, and all of it from one batched ZeroKMS request.
func recordsAndTerms(ctx context.Context, cipher *stackencrypt.Cipher) ([]stackencrypt.EncryptedRecord, error) {
	section("records, and the terms that index them")

	users := []user{
		{ID: 1, Email: "alice@example.com", Age: 34},
		{ID: 2, Email: "bob@example.com", Age: 29},
		{ID: 3, Email: "carol@example.com", Age: 41},
	}
	records, err := cipher.EncryptRecords(ctx, users)
	if err != nil {
		return nil, fmt.Errorf("encrypting records: %w", err)
	}
	fmt.Printf("  %d rows sealed in one batched key request\n", len(records))
	for i, r := range records {
		fmt.Printf("  row %d  Email: %d-byte ciphertext, eq %x…, match %d positions\n",
			i, len(r["Email"].Ciphertext.(stackencrypt.Sealed)), r["Email"].Equality[:6], countPositions(r["Email"].Match))
		fmt.Printf("         Age:   %d-byte ciphertext, eq %x…, ore %d bytes\n",
			len(r["Age"].Ciphertext.(stackencrypt.Sealed)), r["Age"].Equality[:6], len(r["Age"].Ore))
	}

	// A query probe: the same derivation as the stored term, from the value
	// being searched for. It never touches the ciphertext — matching is what
	// the term is for.
	fmt.Println()
	probe, err := cipher.Term(ctx, "bob@example.com", stackencrypt.MustContext("users/email"), stackencrypt.Equality)
	if err != nil {
		return nil, fmt.Errorf("deriving a probe: %w", err)
	}
	for i, r := range records {
		if probe.(stackencrypt.EqualityTerm).Equal(r["Email"].Equality) {
			fmt.Printf("  probe for bob@example.com matches row %d\n", i)
		}
	}

	// A term is bound to its context. The same value under another field's
	// context is a different term, which is what stops a match in one column
	// from being a match in another.
	wrong, err := cipher.Term(ctx, "bob@example.com", stackencrypt.MustContext("users/name"), stackencrypt.Equality)
	if err != nil {
		return nil, fmt.Errorf("deriving a probe: %w", err)
	}
	fmt.Printf("  the same value under users/name matches nothing: %t\n",
		!wrong.(stackencrypt.EqualityTerm).Equal(records[1]["Email"].Equality))

	var back []user
	if err := cipher.DecryptRecords(ctx, records, &back); err != nil {
		return nil, fmt.Errorf("decrypting records: %w", err)
	}
	fmt.Printf("\n  opened      %v\n", back)
	fmt.Printf("  (ID is tagged `-`, so it never crossed the boundary and comes back zero)\n")
	return records, nil
}

// ORE terms compare in the plaintext's order without revealing it: sorting
// the rows by their Age term sorts them by age.
func ordering(records []stackencrypt.EncryptedRecord) error {
	section("order, without the values")

	order := []int{0, 1, 2}
	sort.Slice(order, func(i, j int) bool {
		return records[order[i]]["Age"].Ore.Less(records[order[j]]["Age"].Ore)
	})
	fmt.Printf("  rows sorted by their Age ORE terms: %v\n", order)
	fmt.Printf("  (ages were 34, 29, 41 — so ascending age is row 1, 0, 2)\n")
	return nil
}

func countPositions(t stackencrypt.MatchTerm) int {
	positions, err := t.Positions()
	if err != nil {
		return -1
	}
	return len(positions)
}

func section(title string) {
	fmt.Printf("── %s %s\n", title, dashes(60-len(title)))
}

func dashes(n int) string {
	if n < 0 {
		n = 0
	}
	out := make([]byte, 0, n*3)
	for range n {
		out = append(out, "─"...)
	}
	return string(out)
}
