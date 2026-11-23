package encrypt_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/jackc/pgx/v5/pgconn"
)

// entities hold emergency contacts: Ann's family has one contact who is a
// sibling and another called more than five times, and no one contact who
// is both; Ben's has one; Cy has none.
var entities = []testusers.Entity{
	{ID: 1, CustomFieldValues: testusers.CustomFieldValues{Extra: testusers.CustomFieldExtra{EmergencyContacts: []testusers.EmergencyContact{
		{Name: "Ann", Relationship: "Sibling", PreviousCallCount: 2, Age: 30},
		{Name: "Al", Relationship: "Friend", PreviousCallCount: 9, Age: 50},
	}}}},
	{ID: 2, CustomFieldValues: testusers.CustomFieldValues{Extra: testusers.CustomFieldExtra{EmergencyContacts: []testusers.EmergencyContact{
		{Name: "Bea", Relationship: "Friend", PreviousCallCount: 1, Age: 41},
		{Name: "Ben", Relationship: "Sibling", PreviousCallCount: 7, Age: 25},
	}}}},
	{ID: 3, CustomFieldValues: testusers.CustomFieldValues{Extra: testusers.CustomFieldExtra{EmergencyContacts: []testusers.EmergencyContact{}}}},
}

// The element match inside PostgreSQL with EQL v4 installed: Match finds
// the row where one contact passes both predicates, where an equality and
// an ordering at the array's paths find a row where each passes on a
// different contact too. Skipped unless DATABASE_URL is set.
func TestJSONElementMatchInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	c := deterministicEQLClient(t)
	cipher := c.DefaultKeyset()
	conn := eqlPostgresConn(t, ctx, url)
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE entities (id bigint PRIMARY KEY, custom_field_values public.eql_v4_json_search NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS entities`) })
	encrypted, err := testusers.EncryptEntity(ctx, cipher, entities)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range encrypted {
		if _, err := conn.ExecContext(ctx, `INSERT INTO entities VALUES ($1, $2)`, e.ID, e.CustomFieldValues); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(q string, args ...any) ([]int64, error) {
		t.Helper()
		rows, err := conn.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, id)
		}
		return out, rows.Err()
	}
	want := func(name string, got []int64, err error, want ...int64) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: rows %v, want %v", name, got, want)
		}
	}
	f := testusers.EntityFields.CustomFieldValues
	elementMatch := `SELECT id FROM entities WHERE eql_v4.json_tree_element_match(custom_field_values, $1::eql_v4.query_json_elements) ORDER BY id`
	contact := testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts
	relationship, callCount, age := encrypt.AtPath(contact.Relationship), encrypt.AtPath(contact.PreviousCallCount), encrypt.AtPath(contact.Age)
	match := func(opts encrypt.JSONReadOptions, predicates ...encrypt.ElementPredicate[testusers.EntityCustomFieldValuesFieldElementsExtraEmergencyContacts]) eql.JSONSearchElementsQuery {
		t.Helper()
		q, err := f.Elements.ExtraEmergencyContacts.Match(ctx, cipher, opts, predicates...)
		if err != nil {
			t.Fatal(err)
		}
		return q
	}

	// The superset: some contact is a sibling (EqAt), and some contact was
	// called more than five times (an ordering over every match). Ann's
	// family passes on two different contacts.
	sibling, err := f.EqAt(ctx, cipher, "$.extra.emergency_contacts[*].relationship", "Sibling")
	if err != nil {
		t.Fatal(err)
	}
	calls, err := f.At.ExtraEmergencyContactsPreviousCallCount.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	moreThanFive, err := f.At.ExtraEmergencyContactsPreviousCallCount.Gt(ctx, cipher, 5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ids(`SELECT id FROM entities WHERE custom_field_values @> $1::eql_v4.query_json AND EXISTS (SELECT 1 FROM eql_v4.json_tree_path_query(custom_field_values, $2::text) AS e WHERE e > $3::eql_v4.query_json_leaf) ORDER BY id`, sibling, calls.Selector(), moreThanFive)
	want("an equality and an ordering, any contacts", got, err, 1, 2)

	// One contact passing both: Ben's family alone.
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, relationship.Eq("Sibling"), callCount.Gt(5)))
	want("Match, one contact", got, err, 2)
	// The same members named at run time find the same row.
	named := f.Elements.ExtraEmergencyContacts.Member
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, named("relationship").Eq("Sibling"), named("previous_call_count").Gt(5)))
	want("Match, members named at run time", got, err, 2)
	// Each half alone finds both families, as the superset's halves do.
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, relationship.Eq("Sibling")))
	want("Match, a sibling", got, err, 1, 2)
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, callCount.Gt(5)))
	want("Match, more than five calls", got, err, 1, 2)
	// Three members and a range, on one contact: Ann (30, 2 calls) and
	// Ben (25, 7 calls) are 18 to 40, and only Ben was called more than
	// five times.
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, age.Between(18, 40), callCount.Gte(2), relationship.Eq("Sibling")))
	want("Match, a range", got, err, 1, 2)
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, age.Between(18, 40), callCount.Gt(5)))
	want("Match, a range and more than five calls", got, err, 2)
	// Equality is of the ordering term, which folds case: "sibling"
	// equals "Sibling". EqAt is exact.
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{}, relationship.Eq("sibling"), age.Lt(26)))
	want("Match, folded", got, err, 2)
	exact, err := f.EqAt(ctx, cipher, "$.extra.emergency_contacts[*].relationship", "sibling")
	if err != nil {
		t.Fatal(err)
	}
	got, err = ids(`SELECT id FROM entities WHERE custom_field_values @> $1::eql_v4.query_json ORDER BY id`, exact)
	want("EqAt, exact", got, err)

	// A bound shorter than an array fails the query, rather than answer
	// over part of it: each family has two contacts.
	_, err = ids(elementMatch, match(encrypt.JSONReadOptions{WildcardBound: 1}, relationship.Eq("Sibling")))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22023" {
		t.Errorf("a bound of 1 over two contacts: %v, want SQLSTATE 22023", err)
	}
	// A bound that covers every array answers.
	got, err = ids(elementMatch, match(encrypt.JSONReadOptions{WildcardBound: 2}, relationship.Eq("Sibling"), callCount.Gt(5)))
	want("Match, a bound of 2", got, err, 2)

	// A member the field does not order is refused before the engine is
	// asked, naming it: no Diagnostic, since the guest never saw it.
	_, err = f.Elements.ExtraEmergencyContacts.Match(ctx, cipher, encrypt.JSONReadOptions{}, f.Elements.ExtraEmergencyContacts.Member("name").Eq("Ben"))
	var d *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrTerm) || errors.As(err, &d) {
		t.Errorf("an unordered member: %v", err)
	}
}
