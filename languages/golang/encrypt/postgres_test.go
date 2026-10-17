package encrypt_test

import (
	"context"
	"database/sql"
	"os"
	"slices"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The query methods against a real PostgreSQL, through database/sql and the
// pgx driver: generated rows stored in separate columns, an eq query on the
// equality term, and a matches query whose rows are decrypted and verified.
// The keys are the deterministic test build's, so only the database is
// outside the test. Skipped unless DATABASE_URL names a database the test
// may create a temporary table in.

// matchPositions reads a stored match filter, or a match query's term, as
// the int[] of its little-endian uint16 positions, so PostgreSQL can test
// that a row's filter holds every position of the query with @>.
const matchPositions = `
CREATE FUNCTION pg_temp.match_positions(term bytea) RETURNS int[]
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT coalesce(array_agg(get_byte(term, 2 * i) | (get_byte(term, 2 * i + 1) << 8)), '{}')
  FROM generate_series(0, length(term) / 2 - 1) AS i
$$`

func TestQueriesRunAgainstPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	f := readQueryFixture(t)
	c := queryFixtureClient(t, f)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// One connection: the table and the function are temporary, so they
	// live in this session alone.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for _, stmt := range []string{
		`CREATE TEMPORARY TABLE profiles (
			id         bigint PRIMARY KEY,
			email      bytea NOT NULL,
			email_eq   bytea NOT NULL,
			age        bytea NOT NULL,
			age_eq     bytea NOT NULL,
			age_ore    bytea NOT NULL,
			name       bytea NOT NULL,
			name_match bytea NOT NULL,
			score      bytea NOT NULL,
			score_ore  bytea NOT NULL
		)`,
		matchPositions,
	} {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}

	// The fixture's verify page, as names, and one email each.
	var people []testusers.QueryProfile
	for i, v := range f.Verify.Values {
		if v != nil {
			people = append(people, testusers.QueryProfile{Email: "p" + string(rune('a'+i)) + "@example.com", Age: uint32(20 + i), Name: *v, Score: float64(i) - 1.5})
		}
	}
	encrypted, err := testusers.EncryptQueryProfile(ctx, cipher, people)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO profiles VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			i, e.Email.Ciphertext, e.Email.Equality, e.Age.Ciphertext, e.Age.Equality, e.Age.Ore, e.Name.Ciphertext, e.Name.Match, e.Score.Ciphertext, e.Score.Ore,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.ExecContext(ctx, `ANALYZE profiles`); err != nil {
		t.Fatal(err)
	}

	// eq: the equality term binds as a parameter and finds its one row.
	eq, err := testusers.QueryProfileFields.Email.Eq(ctx, cipher, people[2].Email)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := conn.QueryRowContext(ctx, `SELECT id FROM profiles WHERE email_eq = $1`, eq).Scan(&id); err != nil || id != 2 {
		t.Fatalf("eq found row %d, %v; want 2", id, err)
	}

	// matches: size the fetch, let the server answer, then decrypt the rows
	// it returned and keep those Verify reports true.
	q, err := testusers.QueryProfileFields.Name.Matches(ctx, cipher, f.Verify.Input)
	if err != nil {
		t.Fatal(err)
	}
	var rows uint64
	if err := conn.QueryRowContext(ctx, `SELECT greatest(reltuples, 0)::bigint FROM pg_class WHERE oid = 'profiles'::regclass`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	limit, err := q.TargetLimit(ctx, 10, encrypt.Stats{Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	if _, bounded := limit.Rows(); bounded {
		t.Fatal("a field declared with tags has no expected token count, so with no histogram the limit is unbounded")
	}
	result, err := conn.QueryContext(ctx, `
		SELECT id, email, email_eq, age, age_eq, age_ore, name, name_match, score, score_ore FROM profiles
		WHERE pg_temp.match_positions(name_match) @> pg_temp.match_positions($1)
		ORDER BY id LIMIT $2`, q, limit.FetchOr(50))
	if err != nil {
		t.Fatal(err)
	}
	// Rows hold the connection until they are closed, and the cleanup closes
	// the connection: without this a failure mid-loop would block there.
	defer result.Close()
	var ids []int64
	var fetched []testusers.EncryptedQueryProfile
	for result.Next() {
		var e testusers.EncryptedQueryProfile
		if err := result.Scan(&id, &e.Email.Ciphertext, &e.Email.Equality, &e.Age.Ciphertext, &e.Age.Equality, &e.Age.Ore, &e.Name.Ciphertext, &e.Name.Match, &e.Score.Ciphertext, &e.Score.Ore); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		fetched = append(fetched, e)
	}
	if err := result.Err(); err != nil {
		t.Fatal(err)
	}
	decrypted, err := testusers.DecryptQueryProfile(ctx, cipher, fetched)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(decrypted))
	for i, p := range decrypted {
		names[i] = p.Name
	}
	verified, err := q.Verify(ctx, names)
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for i, ok := range verified {
		if ok {
			hits = append(hits, names[i])
		}
	}

	var want []string
	for i, v := range f.Verify.Values {
		if v != nil && f.Verify.Verified[i] {
			want = append(want, *v)
		}
	}
	if !slices.Equal(hits, want) {
		t.Fatalf("matches %q verified %q from the server's %q (rows %v), want %q", f.Verify.Input, hits, names, ids, want)
	}
	// The server's answer has no false negative: every true match came back.
	for _, w := range want {
		if !slices.Contains(names, w) {
			t.Fatalf("the server did not return %q", w)
		}
	}
}
