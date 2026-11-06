package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return fmt.Errorf("set DATABASE_URL to a PostgreSQL database with EQL v4 installed")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		return fmt.Errorf("open PostgreSQL: %w", err)
	}
	defer db.Close()
	// A temporary table belongs to one connection. Keep that connection for
	// the whole example so the following statements see the same table.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE customers (
		id bigint PRIMARY KEY,
		profile public.eql_v4_json_search NOT NULL
	)`); err != nil {
		return fmt.Errorf("create table (is EQL v4 installed?): %w", err)
	}

	client, err := encrypt.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("connect to ZeroKMS: %w", err)
	}
	defer client.Close()
	cipher := client.DefaultKeyset()
	customers := []Customer{
		{ID: 1, Profile: Profile{Name: "Ada", Age: 35, Visits: []Visit{{At: 10, Place: "home"}, {At: 20, Place: "work"}}}},
		{ID: 2, Profile: Profile{Name: "Bea", Age: 28, Visits: []Visit{{At: 30, Place: "home"}}}},
	}
	sealed, err := Encrypt(ctx, cipher, customers)
	if err != nil {
		return fmt.Errorf("encrypt customers: %w", err)
	}
	for _, customer := range sealed {
		// The EQL value implements driver.Valuer, so database/sql binds it.
		if _, err := conn.ExecContext(ctx, `INSERT INTO customers (id, profile) VALUES ($1, $2)`, customer.ID, customer.Profile); err != nil {
			return fmt.Errorf("insert customer %d: %w", customer.ID, err)
		}
	}

	// A map needle names only the members to test. A Profile value would
	// include its zero-valued fields in the containment query.
	needle, err := Fields.Profile.Contains(ctx, cipher, map[string]any{"name": "Ada"})
	if err != nil {
		return fmt.Errorf("prepare containment query: %w", err)
	}
	var found EncryptedCustomer
	if err := conn.QueryRowContext(ctx,
		`SELECT id, profile FROM customers WHERE profile @> $1::eql_v4.query_json`, needle,
	).Scan(&found.ID, &found.Profile); err != nil {
		return fmt.Errorf("find customer: %w", err)
	}
	opened, err := Decrypt(ctx, cipher, []EncryptedCustomer{found})
	if err != nil {
		return fmt.Errorf("decrypt customer: %w", err)
	}
	fmt.Printf("found customer %d, age %d\n", opened[0].ID, opened[0].Profile.Age)

	// Order comparisons need both the operand and the selector for the same
	// declared path. Cast each SQL parameter to select EQL's operators.
	selector, err := Fields.Profile.At.Age.Selector(ctx, cipher)
	if err != nil {
		return fmt.Errorf("prepare age selector: %w", err)
	}
	older, err := Fields.Profile.At.Age.Gt(ctx, cipher, 30)
	if err != nil {
		return fmt.Errorf("prepare age comparison: %w", err)
	}
	var olderID int64
	if err := conn.QueryRowContext(ctx,
		`SELECT id FROM customers WHERE (profile -> $1::text) > $2::eql_v4.query_json_leaf`,
		selector.Selector(), older,
	).Scan(&olderID); err != nil {
		return fmt.Errorf("find older customer: %w", err)
	}
	fmt.Printf("customer older than 30: %d\n", olderID)

	// Test two members of one visit together: a visit at home after 15.
	// Ada has a visit at home and a visit after 15, but not one visit that
	// is both, so only Bea's row matches. Match compares ordering terms, so
	// "Home" would equal "home": text compares case- and accent-folded.
	// Paths names each visit's members with their Go types, so a value of
	// another type, or a member of another array, does not compile.
	homeLate, err := Fields.Profile.Elements.Visits.Match(ctx, cipher, encrypt.JSONReadOptions{},
		encrypt.AtPath(Paths.Profile.Visits.Place).Eq("home"),
		encrypt.AtPath(Paths.Profile.Visits.At).Gt(15),
	)
	if err != nil {
		return fmt.Errorf("prepare visit match: %w", err)
	}
	var homeLateID int64
	if err := conn.QueryRowContext(ctx,
		`SELECT id FROM customers WHERE eql_v4.json_tree_element_match(profile, $1::eql_v4.query_json_elements)`,
		homeLate,
	).Scan(&homeLateID); err != nil {
		return fmt.Errorf("find a visit at home after 15: %w", err)
	}
	fmt.Printf("customer with a visit at home after 15: %d\n", homeLateID)

	// The same test and an age ordering as one jsonpath predicate and its
	// variables, bound as one parameter. The engine compiles the predicate
	// into the operands above, so the age is the ordering's term and the
	// filter is the visit match. The tree is evaluated in a function, which
	// engages no index: the per-operator queries above are the fast path.
	predicate, err := Fields.Profile.Match(ctx, cipher,
		`$."age" < $max && exists($."visits"[*] ? (@."place" == $place && @."at" > $after))`,
		map[string]any{"max": 30, "place": "home", "after": 15}, encrypt.JSONReadOptions{})
	if err != nil {
		return fmt.Errorf("prepare predicate: %w", err)
	}
	var matchedID int64
	if err := conn.QueryRowContext(ctx,
		`SELECT id FROM customers WHERE profile @@ $1::eql_v4.query_json_predicate`, predicate,
	).Scan(&matchedID); err != nil {
		return fmt.Errorf("find by predicate: %w", err)
	}
	fmt.Printf("customer under 30 with a visit at home after 15: %d\n", matchedID)

	// Read only the visit times of one row. The database returns encrypted
	// entries; Open checks them against the prepared read and returns JSON text.
	read, err := Fields.Profile.Subtree(ctx, cipher, "$.visits[*].at", encrypt.JSONReadOptions{})
	if err != nil {
		return fmt.Errorf("prepare visit read: %w", err)
	}
	rows, err := conn.QueryContext(ctx,
		`SELECT entry FROM customers, eql_v4.json_tree_subtree(profile, $2::text[], 64) AS entry WHERE id = $1`,
		olderID, read.Tokens(),
	)
	if err != nil {
		return fmt.Errorf("read encrypted visits: %w", err)
	}
	defer rows.Close()
	var entries []eql.JSONEntry
	for rows.Next() {
		var entry eql.JSONEntry
		if err := rows.Scan(&entry); err != nil {
			return fmt.Errorf("scan visit entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate visit entries: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close visit rows: %w", err)
	}
	values, err := read.Open(ctx, [][]eql.JSONEntry{entries})
	if err != nil {
		return fmt.Errorf("open visit entries: %w", err)
	}
	for _, value := range values[0] {
		at, err := encrypt.DecodeJSON[int64](value)
		if err != nil {
			return fmt.Errorf("decode visit time: %w", err)
		}
		fmt.Printf("visit at %d\n", at)
	}
	return nil
}
