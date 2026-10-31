package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// EQL v4's TextSearch, sealed and queried through generated code over the
// deterministic guest build with the EQL types. A stored value carries all
// three terms, text that cuts no match token with the empty filter; a query
// carries only the one its operator reads (ADR-0002, amended 2026-10-19), so
// Eq and Lt take a one-letter name and Matches refuses one. A two-letter
// word is a match token of its own, so a two-letter name is matched too.
// packages/eql/tests/encryption/tests/v4_text_search.rs holds the same rules
// against PostgreSQL.

// keysAndTerms is an EQL value's sorted top-level keys, and the value of
// each key.
func keysAndTerms(t *testing.T, value []byte) (string, map[string]json.RawMessage) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		t.Fatalf("the EQL value is not JSON: %v", err)
	}
	if string(raw["v"]) != "4" {
		t.Errorf("v = %s, want 4", raw["v"])
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ","), raw
}

func TestV4TextSearchStoresEveryTermAndQueriesCarryOne(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.EncryptEntry(ctx, cipher, []testusers.Entry{{ID: 1, Name: "Alice"}})
	if err != nil {
		t.Fatal(err)
	}
	keys, stored := keysAndTerms(t, encrypted[0].Name)
	if keys != "bf,c,hm,i,op,v" {
		t.Errorf("stored keys %s, want bf,c,hm,i,op,v", keys)
	}
	decrypted, err := testusers.DecryptEntry(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted[0].Name != "Alice" {
		t.Errorf("opened %q", decrypted[0].Name)
	}

	f := testusers.EntryFields.Name
	// Each method's query carries its operator's term alone, the stored one.
	for _, tc := range []struct {
		method string
		query  func(string) ([]byte, error)
		term   string
	}{
		{"Eq", func(v string) ([]byte, error) { return f.Eq(ctx, cipher, v) }, "hm"},
		{"Lt", func(v string) ([]byte, error) { return f.Lt(ctx, cipher, v) }, "op"},
		{"Gte", func(v string) ([]byte, error) { return f.Gte(ctx, cipher, v) }, "op"},
	} {
		q, err := tc.query("Alice")
		if err != nil {
			t.Fatalf("%s: %v", tc.method, err)
		}
		keys, terms := keysAndTerms(t, q)
		if want := strings.Join(sortedWith("i", "v", tc.term), ","); keys != want {
			t.Errorf("%s query keys %s, want %s", tc.method, keys, want)
		}
		if string(terms[tc.term]) != string(stored[tc.term]) {
			t.Errorf("%s query's %s is not the stored one", tc.method, tc.term)
		}
		// Text that cuts no match token still has an equality and an order
		// term.
		short, err := tc.query("A")
		if err != nil {
			t.Fatalf("%s on one-letter text: %v", tc.method, err)
		}
		if keys, _ := keysAndTerms(t, short); keys != strings.Join(sortedWith("i", "v", tc.term), ",") {
			t.Errorf("%s query keys on one-letter text %s", tc.method, keys)
		}
	}

	m, err := f.Matches(ctx, cipher, "Alice")
	if err != nil {
		t.Fatal(err)
	}
	keys, terms := keysAndTerms(t, m.Query())
	if keys != "bf,i,v" {
		t.Errorf("Matches query keys %s, want bf,i,v", keys)
	}
	if string(terms["bf"]) != string(stored["bf"]) {
		t.Error("the match query's bf is not the stored filter")
	}
	if ok, err := m.Verify(ctx, []string{"alice", "Bob"}); err != nil || !ok[0] || ok[1] {
		t.Errorf("Verify = %v, %v", ok, err)
	}

	// A match query on text that cuts no token is refused, never sent as an
	// empty filter.
	if q, err := f.Matches(ctx, cipher, "A"); !errors.Is(err, encrypt.ErrTerm) {
		t.Errorf("Matches on one-letter text = %v, %v, want ErrTerm", q, err)
	}
	// A two-letter word is one token: "Ng" stores a filter, and the query of
	// "ng" carries the same bits.
	ng, err := testusers.EncryptEntry(ctx, cipher, []testusers.Entry{{ID: 4, Name: "Ng"}})
	if err != nil {
		t.Fatalf("storing a two-letter name in a TextSearch: %v", err)
	}
	_, ngTerms := keysAndTerms(t, ng[0].Name)
	if string(ngTerms["bf"]) == "[]" {
		t.Error(`"Ng" stored the empty filter, want its word token`)
	}
	ngQuery, err := f.Matches(ctx, cipher, "ng")
	if err != nil {
		t.Fatalf("Matches(%q): %v", "ng", err)
	}
	if _, q := keysAndTerms(t, ngQuery.Query()); string(q["bf"]) != string(ngTerms["bf"]) {
		t.Errorf(`the query "ng"'s bf %s is not the stored "Ng"'s %s`, q["bf"], ngTerms["bf"])
	}
	// Storing such text, an empty string included, keeps every term, the
	// match term as the empty filter (where TextMatch refuses the text): Eq
	// and Lt find the row through hm and op, and no Matches query does.
	short, err := testusers.EncryptEntry(ctx, cipher, []testusers.Entry{{ID: 2, Name: "A"}, {ID: 3, Name: ""}})
	if err != nil {
		t.Fatalf("storing short text in a TextSearch: %v", err)
	}
	for i, name := range []string{"A", ""} {
		keys, terms := keysAndTerms(t, short[i].Name)
		if keys != "bf,c,hm,i,op,v" {
			t.Errorf("stored keys for %q %s, want bf,c,hm,i,op,v", name, keys)
		}
		if string(terms["bf"]) != "[]" {
			t.Errorf("stored filter for %q is %s, want []", name, terms["bf"])
		}
		eq, err := f.Eq(ctx, cipher, name)
		if err != nil {
			t.Fatalf("Eq(%q): %v", name, err)
		}
		if _, q := keysAndTerms(t, eq); string(q["hm"]) != string(terms["hm"]) {
			t.Errorf("Eq(%q)'s hm is not the stored one", name)
		}
		lt, err := f.Lt(ctx, cipher, name)
		if err != nil {
			t.Fatalf("Lt(%q): %v", name, err)
		}
		if _, q := keysAndTerms(t, lt); string(q["op"]) != string(terms["op"]) {
			t.Errorf("Lt(%q)'s op is not the stored one", name)
		}
	}
	opened, err := testusers.DecryptEntry(ctx, cipher, short)
	if err != nil {
		t.Fatal(err)
	}
	if opened[0].Name != "A" || opened[1].Name != "" {
		t.Errorf("opened %q and %q", opened[0].Name, opened[1].Name)
	}
}

// sortedWith is the given keys, sorted.
func sortedWith(keys ...string) []string {
	sort.Strings(keys)
	return keys
}
