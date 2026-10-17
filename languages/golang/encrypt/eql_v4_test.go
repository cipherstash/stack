package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The EQL v4 types the engine produces besides TextEq, sealed through
// generated code over the deterministic guest build with the EQL types:
// each Go field type reaches its v4 type's own plan, and the values open
// back to what went in. PostgreSQL sees these values through the Rust
// suite: TestV4RowsMatchTheCommittedFixture commits them to
// v4_rows.json, and packages/eql/tests/encryption inserts that file into
// eql_v4 columns and queries it.

var profiles = []testusers.Profile{
	{ID: 1, Visits: 3, Balance: 1234567890123, Active: true, Ratio: 0.5, Score: 2.25, Note: "a private note", Name: "alice", Age: 42, Rank: 7, Weight: 1.5, Price: 9.75},
	{ID: 2, Visits: 0, Balance: -1, Active: false, Ratio: -1.5, Score: 0, Note: "", Name: "bob smith", Age: 42, Rank: -7, Weight: -1.5, Price: 0},
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "packages", "eql", "tests", "encryption", "fixtures", name)
}

// keysOf is the sorted top-level keys of an EQL value. It also checks the
// envelope: version 4, and the table and column the value was stored under.
func keysOf(t *testing.T, column string, value []byte) string {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		t.Fatalf("the EQL value is not JSON: %v: %s", err, value)
	}
	if string(raw["v"]) != "4" {
		t.Errorf("v = %s, want 4: %s", raw["v"], value)
	}
	var i struct{ T, C string }
	if err := json.Unmarshal(raw["i"], &i); err != nil || i.T != "profiles" || i.C != column {
		t.Errorf("i = %s, want {\"t\":\"profiles\",\"c\":%q}", raw["i"], column)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// stored is each sealed field of an encrypted profile by column.
func stored(e testusers.EncryptedProfile) map[string][]byte {
	return map[string][]byte{
		"visits":  e.Visits,
		"balance": e.Balance,
		"active":  e.Active,
		"ratio":   e.Ratio,
		"score":   e.Score,
		"note":    e.Note,
		"name":    e.Name,
		"age":     e.Age,
		"rank":    e.Rank,
		"weight":  e.Weight,
		"price":   e.Price,
	}
}

func TestV4FieldsSealToTheirEQLTypesAndOpenBack(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.EncryptProfile(ctx, cipher, profiles)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"visits":  "c,i,v",
		"balance": "c,i,v",
		"active":  "c,i,v",
		"ratio":   "c,i,v",
		"score":   "c,i,v",
		"note":    "c,i,v",
		"name":    "bf,c,i,v",
		"age":     "c,hm,i,v",
		"rank":    "c,hm,i,v",
		"weight":  "c,hm,i,v",
		"price":   "c,hm,i,v",
	}
	for i, e := range encrypted {
		for column, value := range stored(e) {
			if got := keysOf(t, column, value); got != want[column] {
				t.Errorf("row %d %s: keys %s, want %s", i, column, got, want[column])
			}
		}
	}

	decrypted, err := testusers.DecryptProfile(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range profiles {
		if decrypted[i] != profiles[i] {
			t.Errorf("row %d: %+v, want %+v", i, decrypted[i], profiles[i])
		}
	}
}

// bloom is the set of filter positions in a TextMatch value or query.
func bloom(t *testing.T, value []byte) map[int]bool {
	t.Helper()
	var v struct {
		BF []int `json:"bf"`
	}
	if err := json.Unmarshal(value, &v); err != nil {
		t.Fatal(err)
	}
	set := make(map[int]bool, len(v.BF))
	for _, p := range v.BF {
		set[p] = true
	}
	return set
}

func subset(a, b map[int]bool) bool {
	for p := range a {
		if !b[p] {
			return false
		}
	}
	return true
}

func TestV4QueriesMatchTheRustFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	raw, err := os.ReadFile(fixturePath("v4_queries.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Table string
		Name  struct {
			Plaintext string
			Query     string
		}
		Age struct {
			Plaintext int32
			Query     string
		}
		Rank struct {
			Plaintext int64
			Query     string
		}
		Weight struct {
			Plaintext float32
			Query     string
		}
		Price struct {
			Plaintext float64
			Query     string
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Table != "profiles" {
		t.Fatalf("the fixture's table changed: %q", fixture.Table)
	}

	// Byte for byte what eql-bindings' own dispatch derived under the same
	// index key: the Go field runs its v4 type's plan and no other.
	name, err := testusers.ProfileFields.Name.Matches(ctx, cipher, fixture.Name.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(name.Query()) != fixture.Name.Query {
		t.Errorf("Name.Matches = %s\nwant             %s", name.Query(), fixture.Name.Query)
	}
	equality := []struct {
		field string
		query func() ([]byte, error)
		want  string
	}{
		{"Age", func() ([]byte, error) {
			return testusers.ProfileFields.Age.Eq(ctx, cipher, fixture.Age.Plaintext)
		}, fixture.Age.Query},
		{"Rank", func() ([]byte, error) {
			return testusers.ProfileFields.Rank.Eq(ctx, cipher, fixture.Rank.Plaintext)
		}, fixture.Rank.Query},
		{"Weight", func() ([]byte, error) {
			return testusers.ProfileFields.Weight.Eq(ctx, cipher, fixture.Weight.Plaintext)
		}, fixture.Weight.Query},
		{"Price", func() ([]byte, error) {
			return testusers.ProfileFields.Price.Eq(ctx, cipher, fixture.Price.Plaintext)
		}, fixture.Price.Query},
	}
	for _, eq := range equality {
		got, err := eq.query()
		if err != nil {
			t.Fatal(err)
		}
		if eq.want == "" || string(got) != eq.want {
			t.Errorf("%s.Eq = %s\nwant     %s", eq.field, got, eq.want)
		}
	}

	// And a stored value holds every filter bit of a query for text it
	// contains, which is what `@@` tests, and not those of text it lacks.
	// The first is a property of the filter. The second is not: a Bloom
	// filter can cover an absent needle's bits by chance, and "zzz" and
	// "bob" are clear of it under testSeed and the pinned configuration
	// only, so a change to either can flip them with no bug behind it.
	encrypted, err := testusers.EncryptProfile(ctx, cipher, profiles[:1])
	if err != nil {
		t.Fatal(err)
	}
	all := bloom(t, encrypted[0].Name)
	for needle, contained := range map[string]bool{"alice": true, "LIC": true, "zzz": false, "bob": false} {
		q, err := testusers.ProfileFields.Name.Matches(ctx, cipher, needle)
		if err != nil {
			t.Fatal(err)
		}
		if got := subset(bloom(t, q.Query()), all); got != contained {
			t.Errorf("%q in %q: %v, want %v", needle, profiles[0].Name, got, contained)
		}
		// Verify decides on the decrypted text, under TextMatch's own
		// tokenizer, whatever the filter says. Verify takes any decrypted
		// values, so the page also holds the case the tokenizer folds and
		// text holding every 3-gram of the needle out of order.
		names := []string{profiles[0].Name, profiles[1].Name, strings.ToUpper(needle), scrambled(needle)}
		verified, err := q.Verify(ctx, names)
		if err != nil {
			t.Fatal(err)
		}
		for i, name := range names {
			if want := holdsTrigrams(name, needle); verified[i] != want {
				t.Errorf("Verify(%q) over %q = %v, want %v", needle, name, verified[i], want)
			}
		}
	}

	// The fetch is sized from the twin's bits: with no measured histogram a
	// data plan states no prior, so no finite fetch is promised.
	q, err := testusers.ProfileFields.Name.Matches(ctx, cipher, "alice")
	if err != nil {
		t.Fatal(err)
	}
	limit, err := q.TargetLimit(ctx, 10, encrypt.Stats{Rows: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if rows, bounded := limit.Rows(); bounded {
		t.Errorf("TargetLimit with no histogram = %d, want unbounded", rows)
	}
	limit, err = q.TargetLimit(ctx, 10, encrypt.Stats{Rows: 1000, Histogram: []encrypt.Bucket{{Bits: 60, Rows: 1000}}})
	if err != nil {
		t.Fatal(err)
	}
	if rows, bounded := limit.Rows(); !bounded || rows < 10 {
		t.Errorf("TargetLimit with a histogram = %d (bounded %v), want at least 10", rows, bounded)
	}

	// A needle too short for a 3-gram has no filter bits, and an empty
	// filter would be a subset of every row's: the engine refuses it.
	for _, short := range []string{"", "al"} {
		if q, err := testusers.ProfileFields.Name.Matches(ctx, cipher, short); err == nil {
			t.Errorf("Name.Matches(%q) = %s, want a refusal", short, q)
		}
	}
}

// rowsFixture is v4_rows.json: the profiles above as the generated code seals
// them under the deterministic guest and testSeed. The Rust suite opens them
// with stack-kms's DeterministicSource over the same seed, and inserts and
// queries them in PostgreSQL.
type rowsFixture struct {
	Comment string       `json:"_comment"`
	Seed    string       `json:"seed"`
	Table   string       `json:"table"`
	Rows    []fixtureRow `json:"rows"`
}

type fixtureRow struct {
	ID        int64                      `json:"id"`
	Plaintext fixturePlain               `json:"plaintext"`
	Stored    map[string]json.RawMessage `json:"stored"`
}

type fixturePlain struct {
	Visits  int32   `json:"visits"`
	Balance int64   `json:"balance"`
	Active  bool    `json:"active"`
	Ratio   float32 `json:"ratio"`
	Score   float64 `json:"score"`
	Note    string  `json:"note"`
	Name    string  `json:"name"`
	Age     int32   `json:"age"`
	Rank    int64   `json:"rank"`
	Weight  float32 `json:"weight"`
	Price   float64 `json:"price"`
}

// TestV4RowsMatchTheCommittedFixture checks the committed v4_rows.json
// against what the generated code seals today. The deterministic guest
// derives every data key from the seed, so the envelopes and the terms
// (`bf`) are the same every run; the AEAD nonce inside each `c` is random,
// so `c` is not. The test therefore compares everything but `c`, and opens
// the committed `c` values with today's code.
//
// EQL_UPDATE_FIXTURES rewrites the file only when something other than the
// ciphertexts moved, so a regeneration that changes nothing leaves no diff.
// EQL_V4_ROWS_OUT names a file to write today's rows to, ciphertexts and
// all: CI hands it to the Rust suite (EQL_V4_ROWS), so the ciphertexts the
// Go SDK seals now are opened by Rust, not only the committed ones.
func TestV4RowsMatchTheCommittedFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	encrypted, err := testusers.EncryptProfile(context.Background(), c.DefaultKeyset(), profiles)
	if err != nil {
		t.Fatal(err)
	}
	fixture := rowsFixture{
		Comment: "Profile rows sealed by the Go SDK's generated code over the deterministic EQL guest with the seed below; the Rust suite opens and queries them. Regenerate with EQL_UPDATE_FIXTURES=1 go test ./encrypt -run TestV4Rows, do not edit.",
		Seed:    string(testSeed[:]),
		Table:   "profiles",
	}
	for i, e := range encrypted {
		p := profiles[i]
		row := fixtureRow{
			ID:        p.ID,
			Plaintext: plainOf(p),
			Stored:    map[string]json.RawMessage{},
		}
		for column, value := range stored(e) {
			row.Stored[column] = json.RawMessage(value)
		}
		fixture.Rows = append(fixture.Rows, row)
	}
	rendered, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	if out := os.Getenv("EQL_V4_ROWS_OUT"); out != "" {
		if err := os.WriteFile(out, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := fixturePath("v4_rows.json")
	var committed rowsFixture
	committedBytes, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(committedBytes, &committed)
	}
	same := err == nil && bytes.Equal(withoutCiphertexts(t, committed), withoutCiphertexts(t, fixture))
	if os.Getenv("EQL_UPDATE_FIXTURES") != "" {
		if same {
			t.Logf("%s: unchanged beyond the ciphertexts; left as it is", path)
		} else {
			if err := os.WriteFile(path, rendered, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: rewritten", path)
			committed, same = fixture, true
		}
	}
	if err != nil && !same {
		t.Fatalf("%v: run with EQL_UPDATE_FIXTURES=1 to write it", err)
	}
	if !same {
		t.Errorf("%s differs from what the generated code seals today beyond the ciphertexts; regenerate it with EQL_UPDATE_FIXTURES=1", path)
	}

	// The committed ciphertexts still open, to the committed plaintexts.
	sealed := make([]testusers.EncryptedProfile, len(committed.Rows))
	for i, row := range committed.Rows {
		sealed[i] = testusers.EncryptedProfile{
			ID:      row.ID,
			Visits:  []byte(row.Stored["visits"]),
			Balance: []byte(row.Stored["balance"]),
			Active:  []byte(row.Stored["active"]),
			Ratio:   []byte(row.Stored["ratio"]),
			Score:   []byte(row.Stored["score"]),
			Note:    []byte(row.Stored["note"]),
			Name:    []byte(row.Stored["name"]),
			Age:     []byte(row.Stored["age"]),
			Rank:    []byte(row.Stored["rank"]),
			Weight:  []byte(row.Stored["weight"]),
			Price:   []byte(row.Stored["price"]),
		}
	}
	opened, err := testusers.DecryptProfile(context.Background(), c.DefaultKeyset(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range committed.Rows {
		if got := plainOf(opened[i]); got != row.Plaintext {
			t.Errorf("row %d opens to %+v, want %+v", row.ID, got, row.Plaintext)
		}
	}
}

// plainOf is a profile's plaintext as the fixture records it.
func plainOf(p testusers.Profile) fixturePlain {
	return fixturePlain{p.Visits, p.Balance, p.Active, p.Ratio, p.Score, p.Note, p.Name, p.Age, p.Rank, p.Weight, p.Price}
}

// withoutCiphertexts renders a fixture with every stored value's `c`
// removed: the part of the file that is the same on every run.
func withoutCiphertexts(t *testing.T, f rowsFixture) []byte {
	t.Helper()
	out := f
	out.Rows = nil
	for _, row := range f.Rows {
		stripped := fixtureRow{ID: row.ID, Plaintext: row.Plaintext, Stored: map[string]json.RawMessage{}}
		for column, value := range row.Stored {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(value, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "c")
			b, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			stripped.Stored[column] = b
		}
		out.Rows = append(out.Rows, stripped)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// holdsTrigrams is TextMatch's verify as a test oracle: the value holds
// every 3-gram of the query, both lower-cased (EqlMatch's options are 3-grams
// with downcasing), and the query cuts at least one.
func holdsTrigrams(value, query string) bool {
	have := map[string]bool{}
	for _, g := range trigrams(strings.ToLower(value)) {
		have[g] = true
	}
	want := trigrams(strings.ToLower(query))
	for _, g := range want {
		if !have[g] {
			return false
		}
	}
	return len(want) > 0
}

func trigrams(s string) []string {
	r := []rune(s)
	var out []string
	for i := 0; i+3 <= len(r); i++ {
		out = append(out, string(r[i:i+3]))
	}
	return out
}

// scrambled holds every 3-gram of s, last first, with a space between them:
// no substring of it is s, and a token test still passes it.
func scrambled(s string) string {
	g := trigrams(s)
	slices.Reverse(g)
	return strings.Join(g, " ")
}
