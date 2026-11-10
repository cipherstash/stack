package encrypt_test

import (
	"context"
	"math"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Encrypted JSON documents of Go types (testusers.Subscriber) inside
// PostgreSQL with EQL v4 installed: stored from structs, found by queries
// whose needles and operands are Go values, and opened back into Go types,
// whole and in part. Skipped unless DATABASE_URL is set.
func TestJSONTypedDocumentsInPostgres(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	c := deterministicEQLClient(t)
	cipher := c.DefaultKeyset()
	conn := eqlPostgresConn(t, ctx, url)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`CREATE TEMP TABLE subscribers (id bigint PRIMARY KEY, profile public.eql_v4_json_search NOT NULL, prefs public.eql_v4_json_search, labels public.eql_v4_json_search NOT NULL)`)
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS subscribers`) })
	encrypted, err := testusers.EncryptSubscriber(ctx, cipher, subscribers)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range encrypted {
		exec(`INSERT INTO subscribers VALUES ($1, $2, $3, $4)`, e.ID, e.Profile, e.Prefs, e.Labels)
	}
	ids := func(q string, args ...any) []int64 {
		t.Helper()
		rows, err := conn.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		defer rows.Close()
		var out []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := func(name string, got []int64, want ...int64) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s: rows %v, want %v", name, got, want)
		}
	}
	must := func(v []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	f := testusers.SubscriberFields.Profile

	// Stored rows, re-serialised by PostgreSQL, open into the declared
	// types: every 64-bit integer and the 17-digit float exactly.
	rows, err := conn.QueryContext(ctx, `SELECT id, profile, prefs, labels FROM subscribers ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var stored []testusers.EncryptedSubscriber
	for rows.Next() {
		var e testusers.EncryptedSubscriber
		if err := rows.Scan(&e.ID, &e.Profile, &e.Prefs, &e.Labels); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	back, err := testusers.DecryptSubscriber(ctx, c, stored)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, subscribers) {
		t.Fatalf("read back:\n got %+v\nwant %+v", back, subscribers)
	}

	// Containment with a needle struct of pointer and omitempty fields: a
	// field left nil is not in the needle.
	contains := `SELECT id FROM subscribers WHERE profile @> $1::eql_v4.query_json ORDER BY id`
	want("contains tier", ids(contains, eql.JSONSearchQuery(must(f.Contains(ctx, cipher, testusers.ProfileNeedle{Tier: ptr("gold")})))), 1)
	want("contains name and age", ids(contains, eql.JSONSearchQuery(must(f.Contains(ctx, cipher, testusers.ProfileNeedle{Name: ptr("Bob"), Age: ptr(int64(7))})))), 2)
	// A map needle names only what it holds; the needle struct's Visit has
	// no omitempty, so its zero Place is in the needle and narrows it: no
	// visit at 3 has an empty place. The narrowing the docs warn of.
	want("contains a visit, map", ids(contains, eql.JSONSearchQuery(must(f.Contains(ctx, cipher, map[string]any{"visits": []map[string]any{{"at": 3}}})))), 1)
	want("contains a visit, zero place", ids(contains, eql.JSONSearchQuery(must(f.Contains(ctx, cipher, testusers.ProfileNeedle{Visits: []testusers.Visit{{At: 3}}})))))
	// Contained by the document type itself: its zero fields widen, so
	// Bob's whole profile contains no other row's.
	want("contained by", ids(`SELECT id FROM subscribers WHERE profile <@ $1::eql_v4.query_json ORDER BY id`, eql.JSONSearchQuery(must(f.ContainedBy(ctx, cipher, subscribers[1].Profile)))), 2)
	// Equality at a path with Go scalars, the integer extremes included.
	want("eq_at umax", ids(contains, eql.JSONSearchQuery(must(f.EqAt(ctx, cipher, "$.big", uint64(math.MaxUint64))))), 1)
	want("eq_at min", ids(contains, eql.JSONSearchQuery(must(f.EqAt(ctx, cipher, "$.small", int64(math.MinInt64))))), 1)
	want("eq_at name", ids(contains, eql.JSONSearchQuery(must(f.EqAt(ctx, cipher, "$.name", "Carol")))), 3)
	want("eq_at a visit", ids(contains, eql.JSONSearchQuery(must(f.EqAt(ctx, cipher, "$.visits[*].at", 5)))), 2)
	// The optional and the map columns.
	want("prefs contains", ids(`SELECT id FROM subscribers WHERE prefs @> $1::eql_v4.query_json ORDER BY id`, eql.JSONSearchQuery(must(testusers.SubscriberFields.Prefs.Contains(ctx, cipher, map[string]string{"theme": "dark"})))), 1)
	want("labels contains", ids(`SELECT id FROM subscribers WHERE labels @> $1::eql_v4.query_json ORDER BY id`, eql.JSONSearchQuery(must(testusers.SubscriberFields.Labels.Contains(ctx, cipher, map[string]string{"team": "red"})))), 1)

	// Orderings with Go numbers.
	age, err := f.At.Age.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	gt, err := f.At.Age.Gt(ctx, cipher, 30)
	if err != nil {
		t.Fatal(err)
	}
	want("age > 30", ids(`SELECT id FROM subscribers WHERE (profile -> $1::text) > $2::eql_v4.query_json_leaf ORDER BY id`, age.Selector(), gt), 1, 3)
	rng, err := f.At.Age.Between(ctx, cipher, int64(5), 40.5)
	if err != nil {
		t.Fatal(err)
	}
	want("age between", ids(`SELECT id FROM subscribers WHERE (profile -> $1::text) >= $2::eql_v4.query_json_leaf AND (profile -> $1::text) <= $3::eql_v4.query_json_leaf ORDER BY id`, age.Selector(), rng.Low, rng.High), 1, 2)

	// `->` opened, and each value decoded into a Go type.
	selected := func(sel encrypt.JSONSelection[eql.JSONEntry]) []encrypt.JSONValue {
		t.Helper()
		rows, err := conn.QueryContext(ctx, `SELECT profile -> $1::text FROM subscribers ORDER BY id`, sel.Selector())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var entries []*eql.JSONEntry
		for rows.Next() {
			var e *eql.JSONEntry
			if err := rows.Scan(&e); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		values, err := sel.Open(ctx, entries)
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	big, err := f.Selector(ctx, cipher, "$.big")
	if err != nil {
		t.Fatal(err)
	}
	var bigs []uint64
	for _, v := range selected(big) {
		n, err := encrypt.DecodeJSON[uint64](v.JSON)
		if err != nil || !v.Found {
			t.Fatalf("$.big: %+v %v", v, err)
		}
		bigs = append(bigs, n)
	}
	if !slices.Equal(bigs, []uint64{math.MaxUint64, math.MaxInt64, 0}) {
		t.Errorf("$.big: %v", bigs)
	}
	score, err := f.Selector(ctx, cipher, "$.score")
	if err != nil {
		t.Fatal(err)
	}
	if s, err := encrypt.DecodeJSON[float64](selected(score)[0].JSON); err != nil || s != 0.30000000000000004 {
		t.Errorf("$.score: %v %v", s, err)
	}
	// The sealed root at $ opens to the whole document, which decodes into
	// the field's own type.
	root, err := f.Selector(ctx, cipher, "$")
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range selected(root) {
		p, err := encrypt.DecodeJSON[testusers.SubscriberProfile](v.JSON)
		if err != nil || !reflect.DeepEqual(p, subscribers[i].Profile) {
			t.Errorf("$ row %d: %+v %v", i, p, err)
		}
	}

	// A subtree read, each value decoded: every visit of each row, then one
	// row's visits as one slice.
	subtree := func(read encrypt.JSONRead[eql.JSONEntry], id int64) []eql.JSONEntry {
		t.Helper()
		rows, err := conn.QueryContext(ctx, `SELECT e FROM subscribers, eql_v4.json_tree_subtree(profile, $2::text[]) AS e WHERE id = $1`, id, read.Tokens())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var entries []eql.JSONEntry
		for rows.Next() {
			var e eql.JSONEntry
			if err := rows.Scan(&e); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return entries
	}
	each, err := f.Subtree(ctx, cipher, "$.visits[*]", encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	groups := make([][]eql.JSONEntry, len(subscribers))
	for i, s := range subscribers {
		groups[i] = subtree(each, s.ID)
	}
	opened, err := each.Open(ctx, groups)
	if err != nil {
		t.Fatal(err)
	}
	for i, values := range opened {
		var visits []testusers.Visit
		for _, text := range values {
			v, err := encrypt.DecodeJSON[testusers.Visit](text)
			if err != nil {
				t.Fatal(err)
			}
			visits = append(visits, v)
		}
		if len(visits) != len(subscribers[i].Profile.Visits) || (len(visits) > 0 && !reflect.DeepEqual(visits, subscribers[i].Profile.Visits)) {
			t.Errorf("visits of row %d: %+v", i, visits)
		}
	}
	all, err := f.Subtree(ctx, cipher, "$.visits", encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	one, err := all.OpenOne(ctx, subtree(all, 1))
	if err != nil || !one.Found {
		t.Fatalf("OpenOne $.visits: %+v %v", one, err)
	}
	if visits, err := encrypt.DecodeJSON[[]testusers.Visit](one.JSON); err != nil || !reflect.DeepEqual(visits, subscribers[0].Profile.Visits) {
		t.Errorf("$.visits as a slice: %+v %v", visits, err)
	}
}
