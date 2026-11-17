package witheql_test

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"slices"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// TestEncryptTestClientInPostgres is an application's test end to end:
// create the test client, encrypt with generated code, insert into an EQL v4
// column, search on the ciphertext, and decrypt what the database returns.
//
// Skipped unless DATABASE_URL is set. With it set, EQL v4 must be installed
// there. `mise run go:test:postgres` sets both and fails on a skip.
func TestEncryptTestClientInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := t.Context()

	// 1. The test client: one cipher for each tenant's keyset.
	client := encrypttest.NewClient(t)
	cipher := client.Keyset(encrypt.KeysetName("tenant-a"))

	// 2. Encrypt with generated code.
	contacts := []testusers.Contact{
		{ID: 1, Email: "ada@example.com", Notes: "first"},
		{ID: 2, Email: "grace@example.com", Notes: "second"},
	}
	rows, err := testusers.EncryptContact(ctx, cipher, contacts)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Insert into an EQL v4 column.
	conn := postgres(t, ctx, url)
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, stmt, args...); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec(`CREATE TEMPORARY TABLE encrypttest_contacts (id bigint PRIMARY KEY, email eql_v4_text_eq NOT NULL, notes bytea NOT NULL)`)
	for _, r := range rows {
		exec(`INSERT INTO encrypttest_contacts VALUES ($1, $2::text::jsonb::eql_v4_text_eq, $3)`, r.ID, r.Email, []byte(r.Notes.Ciphertext))
	}

	// 4. Search on the ciphertext.
	query, err := testusers.ContactFields.Email.Eq(ctx, cipher, "grace@example.com")
	if err != nil {
		t.Fatal(err)
	}
	found, err := conn.QueryContext(ctx, `SELECT id, email::text, notes FROM encrypttest_contacts WHERE email = $1::text::jsonb::eql_v4.query_text_eq ORDER BY id`, query)
	if err != nil {
		t.Fatal(err)
	}
	defer found.Close()
	var read []testusers.EncryptedContact
	for found.Next() {
		var r testusers.EncryptedContact
		var email string
		var notes []byte
		if err := found.Scan(&r.ID, &email, &notes); err != nil {
			t.Fatal(err)
		}
		r.Email, r.Notes.Ciphertext = eql.TextEq(email), notes
		read = append(read, r)
	}
	if err := found.Err(); err != nil {
		t.Fatal(err)
	}
	if ids := idsOf(read); !slices.Equal(ids, []int64{2}) {
		t.Fatalf("the query found rows %v, want [2]", ids)
	}

	// 5. Decrypt and assert.
	back, err := testusers.DecryptContact(ctx, client, read)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, contacts[1:]) {
		t.Fatalf("%+v, want %+v", back, contacts[1:])
	}
}

func idsOf(rows []testusers.EncryptedContact) []int64 {
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return ids
}

// postgres is one connection to url, which must have EQL v4 installed. One
// connection, because the table is temporary.
func postgres(t *testing.T, ctx context.Context, url string) *sql.Conn {
	t.Helper()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var installed bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regnamespace('eql_v4') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("EQL v4 is not installed in DATABASE_URL; run `mise run go:test:postgres`")
	}
	return conn
}
