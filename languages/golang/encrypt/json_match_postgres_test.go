package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/jackc/pgx/v5/pgconn"
)

func f64(v float64) *float64 { return &v }
func str(v string) *string   { return &v }

// predicateEntities are documents for the seven filters of a customer's
// AIP-160 request, each written as plaintext jsonb_path_match takes it:
// scores, countries (one in another case), weights (one at the bound),
// postcodes present, JSON null and absent, preferred languages, and
// emergency contacts where one contact is a sibling called more than five
// times (2, 5) or the two halves are on different contacts (1, 6).
var predicateEntities = []testusers.Entity{
	{ID: 1, CustomFieldValues: testusers.CustomFieldValues{
		Score: f64(3.14), Weight: f64(5), Address: &testusers.CustomAddress{Postcode: str("6011")},
		Extra: testusers.CustomFieldExtra{Country: "nz", PreferredLanguages: []string{"csharp", "go"}, EmergencyContacts: []testusers.EmergencyContact{
			{Name: "Ann", Relationship: "Sibling", PreviousCallCount: 2, Age: 30},
			{Name: "Al", Relationship: "Friend", PreviousCallCount: 9, Age: 50},
		}},
	}},
	{ID: 2, CustomFieldValues: testusers.CustomFieldValues{
		Score: f64(2), Weight: f64(12.5), Address: &testusers.CustomAddress{},
		Extra: testusers.CustomFieldExtra{Country: "au", PreferredLanguages: []string{"rust"}, EmergencyContacts: []testusers.EmergencyContact{
			{Name: "Bea", Relationship: "Friend", PreviousCallCount: 1, Age: 41},
			{Name: "Ben", Relationship: "Sibling", PreviousCallCount: 7, Age: 25},
		}},
	}},
	{ID: 3, CustomFieldValues: testusers.CustomFieldValues{
		Weight: f64(9.5),
		Extra:  testusers.CustomFieldExtra{Country: "nz", PreferredLanguages: []string{"python", "rust"}, EmergencyContacts: []testusers.EmergencyContact{}},
	}},
	{ID: 4, CustomFieldValues: testusers.CustomFieldValues{
		Score: f64(3.14), Address: &testusers.CustomAddress{Postcode: str("2000")},
		Extra: testusers.CustomFieldExtra{EmergencyContacts: []testusers.EmergencyContact{
			{Name: "Cy", Relationship: "Friend", PreviousCallCount: 1, Age: 60},
		}},
	}},
	{ID: 5, CustomFieldValues: testusers.CustomFieldValues{
		Score: f64(1), Weight: f64(1.25), Address: &testusers.CustomAddress{Postcode: str("0632")},
		Extra: testusers.CustomFieldExtra{Country: "NZ", PreferredLanguages: []string{"csharp", "python"}, EmergencyContacts: []testusers.EmergencyContact{
			{Name: "Di", Relationship: "Sibling", PreviousCallCount: 6, Age: 33},
		}},
	}},
	{ID: 6, CustomFieldValues: testusers.CustomFieldValues{
		Score: f64(3.14), Weight: f64(9.49),
		Extra: testusers.CustomFieldExtra{Country: "nz", PreferredLanguages: []string{"go"}, EmergencyContacts: []testusers.EmergencyContact{
			{Name: "Ed", Relationship: "Parent", PreviousCallCount: 12, Age: 70},
			{Name: "Flo", Relationship: "Sibling", PreviousCallCount: 0, Age: 40},
		}},
	}},
}

// Match inside PostgreSQL with EQL v4 installed, for the seven filters of
// the request: for each, the @@ form and the json_tree_match form return
// the rows the query written per operator returns, and the rows
// jsonb_path_match returns over the plaintexts. Skipped unless
// DATABASE_URL is set.
func TestJSONPredicateMatchInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	c := deterministicEQLClient(t)
	cipher := c.DefaultKeyset()
	conn := eqlPostgresConn(t, ctx, url)
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE entity (id bigint PRIMARY KEY, custom_field_values public.eql_v4_json_search NOT NULL, plain jsonb NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS entity`) })
	encrypted, err := testusers.EncryptEntity(ctx, cipher, predicateEntities)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		plain, err := json.Marshal(predicateEntities[i].CustomFieldValues)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO entity VALUES ($1, $2, $3)`, e.ID, e.CustomFieldValues, string(plain)); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(q string, args ...any) ([]int64, error) {
		t.Helper()
		rows, err := conn.QueryContext(ctx, q+` ORDER BY id`, args...)
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
	// must is an operand as the text it binds as, cast to its domain.
	must := func(q []byte, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return string(q)
	}
	f := testusers.EntityFields.CustomFieldValues
	selector := func(path string) string {
		t.Helper()
		s, err := f.Selector(ctx, cipher, path)
		if err != nil {
			t.Fatal(err)
		}
		return string(s.Selector())
	}
	weight, err := f.At.Weight.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	languages := "$.extra.preferred_languages[*]"

	for _, tc := range []struct {
		name      string
		predicate string
		vars      map[string]any
		// The same filter written per operator, and its parameters.
		perOperator string
		args        []any
		want        []int64
	}{
		{
			name: "1 equality", predicate: `$."score" == $val`, vars: map[string]any{"val": 3.14},
			perOperator: `SELECT id FROM entity WHERE custom_field_values @> $1::eql_v4.query_json`,
			args:        []any{must(f.EqAt(ctx, cipher, "$.score", 3.14))},
			want:        []int64{1, 4, 6},
		},
		{
			name: "2 nested equality", predicate: `$."extra"."country" == $val`, vars: map[string]any{"val": "nz"},
			perOperator: `SELECT id FROM entity WHERE custom_field_values @> $1::eql_v4.query_json`,
			args:        []any{must(f.EqAt(ctx, cipher, "$.extra.country", "nz"))},
			want:        []int64{1, 3, 6},
		},
		{
			name: "3 range on an ordered path", predicate: `$."weight" < $val`, vars: map[string]any{"val": 9.5},
			perOperator: `SELECT id FROM entity WHERE (custom_field_values -> $1::text) < $2::eql_v4.query_json_leaf`,
			args:        []any{string(weight.Selector()), must(f.At.Weight.Lt(ctx, cipher, 9.5))},
			want:        []int64{1, 5, 6},
		},
		{
			name: "4 presence, not JSON null", predicate: `$."address"."postcode" != null`, vars: map[string]any{},
			perOperator: `SELECT id FROM entity WHERE eql_v4.json_tree_path_exists(custom_field_values, $1::text) AND NOT (custom_field_values @> $2::eql_v4.query_json)`,
			args:        []any{selector("$.address.postcode"), must(f.EqAt(ctx, cipher, "$.address.postcode", nil))},
			want:        []int64{1, 4, 5},
		},
		{
			name: "5 array membership with NOT", predicate: `!(exists($."extra"."preferred_languages"[*] ? (@ == $val1)))`, vars: map[string]any{"val1": "csharp"},
			perOperator: `SELECT id FROM entity WHERE NOT (custom_field_values @> $1::eql_v4.query_json)`,
			args:        []any{must(f.EqAt(ctx, cipher, languages, "csharp"))},
			want:        []int64{2, 3, 4, 6},
		},
		{
			name: "6 boolean composition",
			predicate: `((exists($."extra"."preferred_languages"[*] ? (@ == $val1))
  || exists($."extra"."preferred_languages"[*] ? (@ == $val2)))
  && !(exists($."extra"."preferred_languages"[*] ? (@ == $val3))))`,
			vars:        map[string]any{"val1": "csharp", "val2": "rust", "val3": "python"},
			perOperator: `SELECT id FROM entity WHERE (custom_field_values @> $1::eql_v4.query_json OR custom_field_values @> $2::eql_v4.query_json) AND NOT (custom_field_values @> $3::eql_v4.query_json)`,
			args:        []any{must(f.EqAt(ctx, cipher, languages, "csharp")), must(f.EqAt(ctx, cipher, languages, "rust")), must(f.EqAt(ctx, cipher, languages, "python"))},
			want:        []int64{1, 2},
		},
		{
			name:        "7 element-scoped",
			predicate:   `exists($."extra"."emergency_contacts"[*] ? ((@."relationship" == $val1 && @."previous_call_count" > $val2)))`,
			vars:        map[string]any{"val1": "Sibling", "val2": 5},
			perOperator: `SELECT id FROM entity WHERE eql_v4.json_tree_element_match(custom_field_values, $1::eql_v4.query_json_elements)`,
			args: []any{must(f.Elements.ExtraEmergencyContacts.Match(ctx, cipher, encrypt.JSONReadOptions{},
				encrypt.AtPath(testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts.Relationship).Eq("Sibling"),
				encrypt.AtPath(testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts.PreviousCallCount).Gt(5),
			))},
			want: []int64{2, 5},
		},
	} {
		q, err := f.Match(ctx, cipher, tc.predicate, tc.vars, encrypt.JSONReadOptions{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		vars, err := json.Marshal(tc.vars)
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range []struct {
			name string
			sql  string
			args []any
		}{
			{"@@", `SELECT id FROM entity WHERE custom_field_values @@ $1::eql_v4.query_json_predicate`, []any{q}},
			{"json_tree_match", `SELECT id FROM entity WHERE eql_v4.json_tree_match(custom_field_values, $1::eql_v4.query_json_predicate)`, []any{q}},
			{"per operator", tc.perOperator, tc.args},
			{"jsonb_path_match over the plaintext", `SELECT id FROM entity WHERE jsonb_path_match(plain, $1::jsonpath, $2::jsonb)`, []any{tc.predicate, string(vars)}},
		} {
			got, err := ids(form.sql, form.args...)
			if err != nil {
				t.Fatalf("%s, %s: %v", tc.name, form.name, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("%s, %s: rows %v, want %v", tc.name, form.name, got, tc.want)
			}
		}
	}

	// The element-scoped filter reads each array to the bound: one shorter
	// than an array fails the query, rather than answer over part of it.
	short, err := f.Match(ctx, cipher, `exists($.extra.emergency_contacts[*] ? (@.relationship == $r && @.previous_call_count > $n))`,
		map[string]any{"r": "Sibling", "n": 5}, encrypt.JSONReadOptions{WildcardBound: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ids(`SELECT id FROM entity WHERE custom_field_values @@ $1::eql_v4.query_json_predicate`, short)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22023" {
		t.Errorf("a bound of 1 over two contacts: %v, want SQLSTATE 22023", err)
	}

	// nil vars bind as SQL NULL, as they do for plaintext jsonb_path_match:
	// no row matches, under @@ and json_tree_match alike.
	none, err := f.Match(ctx, cipher, `$.extra.country == $val`, nil, encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT id FROM entity WHERE custom_field_values @@ $1::eql_v4.query_json_predicate`,
		`SELECT id FROM entity WHERE eql_v4.json_tree_match(custom_field_values, $1::eql_v4.query_json_predicate)`,
	} {
		got, err := ids(q, none)
		if err != nil || len(got) != 0 {
			t.Errorf("nil vars: %s = %v (%v), want no rows", q, got, err)
		}
	}
}
