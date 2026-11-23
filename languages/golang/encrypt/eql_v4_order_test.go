package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The OPE-ordered EQL v4 types (IntegerOrd, BigintOrd, RealOrd, DoubleOrd,
// TextOrd and their OrdOpe twins), sealed through generated code over the
// deterministic guest build with the EQL types. PostgreSQL sees these
// values through the Rust suite: TestV4OrderedRowsMatchTheCommittedFixture
// commits them to v4_ordered_rows.json, and
// packages/eql/tests/encryption/tests/v4_order.rs inserts that file into
// eql_v4 columns and compares it.

// rankings are ordered by every field's order key: each row's value is
// below the next row's in every column, except the pairs rankingTies
// records.
var rankings = []testusers.Ranking{
	{ID: 1, Level: -5, Floor: -5, Points: math.MinInt64, Total: -1 << 40, Speed: float32(math.Inf(-1)), Pace: -2.5, Score: -1.5, Mean: math.Inf(-1), Title: "alice", Handle: "al"},
	{ID: 2, Level: 0, Floor: 0, Points: 0, Total: 0, Speed: 0, Pace: 0, Score: 0, Mean: 0, Title: "Cafe", Handle: "bob"},
	{ID: 3, Level: 0, Floor: 0, Points: 0, Total: 0, Speed: float32(math.Copysign(0, -1)), Pace: float32(math.Copysign(0, -1)), Score: math.Copysign(0, -1), Mean: math.Copysign(0, -1), Title: "café", Handle: "BOB"},
	{ID: 4, Level: 7, Floor: 70000, Points: 5_000_000_001, Total: 1 << 40, Speed: 2.5, Pace: 1.5, Score: 9.75, Mean: 1e300, Title: "Mango", Handle: "carol"},
	{ID: 5, Level: math.MaxInt32, Floor: math.MaxInt32, Points: math.MaxInt64, Total: math.MaxInt64, Speed: float32(math.Inf(1)), Pace: float32(math.Inf(1)), Score: math.Inf(1), Mean: math.Inf(1), Title: "Zoe", Handle: "zed"},
}

// rankingTies are the adjacent pairs of rankings, by ID, that tie in every
// order key: equal integers, -0.0 against 0.0, and text that differs only
// in case and accents. They are written down rather than derived because
// the text ties need Unicode case folding, which the engine does and this
// module has no dependency for.
var rankingTies = map[[2]int64]bool{{2, 3}: true}

// storedRanking is each sealed field of an encrypted ranking by column.
func storedRanking(e testusers.EncryptedRanking) map[string][]byte {
	return map[string][]byte{
		"level":  e.Level,
		"floor":  e.Floor,
		"points": e.Points,
		"total":  e.Total,
		"speed":  e.Speed,
		"pace":   e.Pace,
		"score":  e.Score,
		"mean":   e.Mean,
		"title":  e.Title,
		"handle": e.Handle,
	}
}

// orderTerm is a stored value's or query's `op`, as its hex. Lower-case
// hex sorts as the bytes it encodes, which is how EQL compares `op`.
func orderTerm(t *testing.T, value []byte) string {
	t.Helper()
	var v struct {
		OP string `json:"op"`
	}
	if err := json.Unmarshal(value, &v); err != nil || v.OP == "" {
		t.Fatalf("no op in %s: %v", value, err)
	}
	return v.OP
}

func TestV4OrderedFieldsSealToTheirEQLTypesAndOpenBack(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.EncryptRanking(ctx, cipher, rankings)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		for column, value := range storedRanking(e) {
			want := "c,i,op,v"
			if column == "title" || column == "handle" {
				want = "c,hm,i,op,v"
			}
			if got := rankingKeys(t, column, value); got != want {
				t.Errorf("row %d %s: keys %s, want %s", i, column, got, want)
			}
		}
	}

	// The stored order terms sort as the rows do: each row below the next,
	// except the pairs rankingTies records. A recorded tie that is not an
	// adjacent pair of rankings would be checked as nothing, so each one
	// must be found, its numbers must be equal in Go too, and there must be
	// at least one.
	if len(rankingTies) == 0 {
		t.Fatal("rankingTies records no tie: the equal-order-key case is untested")
	}
	found := map[[2]int64]bool{}
	for i := 0; i+1 < len(rankings); i++ {
		a, b := rankings[i], rankings[i+1]
		pair := [2]int64{a.ID, b.ID}
		if !rankingTies[pair] {
			continue
		}
		found[pair] = true
		if a.Level != b.Level || a.Floor != b.Floor || a.Points != b.Points || a.Total != b.Total ||
			a.Speed != b.Speed || a.Pace != b.Pace || a.Score != b.Score || a.Mean != b.Mean {
			t.Errorf("rows %d and %d are recorded as a tie but their numbers differ", a.ID, b.ID)
		}
	}
	for pair := range rankingTies {
		if !found[pair] {
			t.Errorf("rankingTies records rows %d and %d, which are not adjacent in rankings", pair[0], pair[1])
		}
	}
	for column := range storedRanking(encrypted[0]) {
		for i := 0; i+1 < len(encrypted); i++ {
			a := orderTerm(t, storedRanking(encrypted[i])[column])
			b := orderTerm(t, storedRanking(encrypted[i+1])[column])
			tie := rankingTies[[2]int64{rankings[i].ID, rankings[i+1].ID}]
			switch {
			case tie && a != b:
				t.Errorf("%s: rows %d and %d tie in the order key but store different terms", column, rankings[i].ID, rankings[i+1].ID)
			case !tie && a >= b:
				t.Errorf("%s: row %d's term does not sort below row %d's", column, rankings[i].ID, rankings[i+1].ID)
			}
		}
	}

	decrypted, err := testusers.DecryptRanking(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rankings {
		got, want := decrypted[i], rankings[i]
		// The ciphertext keeps -0.0's sign; == would not tell.
		if math.Signbit(float64(got.Speed)) != math.Signbit(float64(want.Speed)) || math.Signbit(got.Mean) != math.Signbit(want.Mean) {
			t.Errorf("row %d: a zero lost its sign", want.ID)
		}
		if got != want {
			t.Errorf("row %d: %+v, want %+v", i, got, want)
		}
	}
}

// rankingKeys is the sorted top-level keys of an EQL value stored under
// rankings, checking its envelope as keysOf does for profiles.
func rankingKeys(t *testing.T, column string, value []byte) string {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		t.Fatalf("the EQL value is not JSON: %v: %s", err, value)
	}
	var i struct{ T, C string }
	if err := json.Unmarshal(raw["i"], &i); err != nil || i.T != "rankings" || i.C != column {
		t.Errorf("i = %s, want {\"t\":\"rankings\",\"c\":%q}", raw["i"], column)
	}
	if string(raw["v"]) != "4" {
		t.Errorf("v = %s, want 4", raw["v"])
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestV4OrderedQueriesMatchTheRustFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	raw, err := os.ReadFile(fixturePath("v4_ordered_queries.json"))
	if err != nil {
		t.Fatal(err)
	}
	type entry[T any] struct {
		Plaintext T
		Query     string
	}
	var fixture struct {
		Table  string
		Level  entry[int32]
		Floor  entry[int32]
		Points entry[int64]
		Total  entry[int64]
		Speed  entry[float32]
		Pace   entry[float32]
		Score  entry[float64]
		Mean   entry[float64]
		Title  entry[string]
		Handle entry[string]
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Table != "rankings" {
		t.Fatalf("the fixture's table changed: %q", fixture.Table)
	}
	f := testusers.RankingFields
	// Byte for byte what eql-bindings' own dispatch derived under the same
	// index key. Every ordering method of a field returns one operand: the
	// operator is SQL's.
	cases := []struct {
		field string
		lt    func() ([]byte, error)
		gte   func() ([]byte, error)
		want  string
	}{
		{"Level", func() ([]byte, error) { return f.Level.Lt(ctx, cipher, fixture.Level.Plaintext) }, func() ([]byte, error) { return f.Level.Gte(ctx, cipher, fixture.Level.Plaintext) }, fixture.Level.Query},
		{"Floor", func() ([]byte, error) { return f.Floor.Lt(ctx, cipher, fixture.Floor.Plaintext) }, func() ([]byte, error) { return f.Floor.Gte(ctx, cipher, fixture.Floor.Plaintext) }, fixture.Floor.Query},
		{"Points", func() ([]byte, error) { return f.Points.Lt(ctx, cipher, fixture.Points.Plaintext) }, func() ([]byte, error) { return f.Points.Gte(ctx, cipher, fixture.Points.Plaintext) }, fixture.Points.Query},
		{"Total", func() ([]byte, error) { return f.Total.Lt(ctx, cipher, fixture.Total.Plaintext) }, func() ([]byte, error) { return f.Total.Gte(ctx, cipher, fixture.Total.Plaintext) }, fixture.Total.Query},
		{"Speed", func() ([]byte, error) { return f.Speed.Lt(ctx, cipher, fixture.Speed.Plaintext) }, func() ([]byte, error) { return f.Speed.Gte(ctx, cipher, fixture.Speed.Plaintext) }, fixture.Speed.Query},
		{"Pace", func() ([]byte, error) { return f.Pace.Lt(ctx, cipher, fixture.Pace.Plaintext) }, func() ([]byte, error) { return f.Pace.Gte(ctx, cipher, fixture.Pace.Plaintext) }, fixture.Pace.Query},
		{"Score", func() ([]byte, error) { return f.Score.Lt(ctx, cipher, fixture.Score.Plaintext) }, func() ([]byte, error) { return f.Score.Gte(ctx, cipher, fixture.Score.Plaintext) }, fixture.Score.Query},
		{"Mean", func() ([]byte, error) { return f.Mean.Lt(ctx, cipher, fixture.Mean.Plaintext) }, func() ([]byte, error) { return f.Mean.Gte(ctx, cipher, fixture.Mean.Plaintext) }, fixture.Mean.Query},
		{"Title", func() ([]byte, error) { return f.Title.Lt(ctx, cipher, fixture.Title.Plaintext) }, func() ([]byte, error) { return f.Title.Eq(ctx, cipher, fixture.Title.Plaintext) }, fixture.Title.Query},
		{"Handle", func() ([]byte, error) { return f.Handle.Lt(ctx, cipher, fixture.Handle.Plaintext) }, func() ([]byte, error) { return f.Handle.Eq(ctx, cipher, fixture.Handle.Plaintext) }, fixture.Handle.Query},
	}
	for _, tc := range cases {
		for _, method := range []func() ([]byte, error){tc.lt, tc.gte} {
			got, err := method()
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" || string(got) != tc.want {
				t.Errorf("%s = %s\nwant %s", tc.field, got, tc.want)
			}
		}
	}

	// Text with a code point Unicode 16 does not assign has no fold, so no
	// order term.
	if q, err := f.Title.Lt(ctx, cipher, "a͸b"); err == nil {
		t.Errorf("Title.Lt over unassigned text = %s, want a refusal", q)
	}
}

// orderedRowsFixture is v4_ordered_rows.json: the rankings above as the
// generated code seals them under the deterministic guest and testSeed.
type orderedRowsFixture struct {
	Comment string       `json:"_comment"`
	Seed    string       `json:"seed"`
	Table   string       `json:"table"`
	Rows    []orderedRow `json:"rows"`
}

type orderedRow struct {
	ID        int64                      `json:"id"`
	Plaintext orderedPlain               `json:"plaintext"`
	Stored    map[string]json.RawMessage `json:"stored"`
}

// orderedPlain is a ranking's plaintext as the fixture records it. JSON has
// no infinity, so the fixture's rows hold finite values only; the infinite
// and -0.0 cases are covered by TestV4OrderedFieldsSealToTheirEQLTypesAndOpenBack
// and the Rust suite.
type orderedPlain struct {
	Level  int32   `json:"level"`
	Floor  int32   `json:"floor"`
	Points int64   `json:"points"`
	Total  int64   `json:"total"`
	Speed  float32 `json:"speed"`
	Pace   float32 `json:"pace"`
	Score  float64 `json:"score"`
	Mean   float64 `json:"mean"`
	Title  string  `json:"title"`
	Handle string  `json:"handle"`
}

func orderedPlainOf(r testusers.Ranking) orderedPlain {
	return orderedPlain{r.Level, r.Floor, r.Points, r.Total, r.Speed, r.Pace, r.Score, r.Mean, r.Title, r.Handle}
}

// fixtureRankings are the rows v4_ordered_rows.json holds: finite values
// on both sides of the fixture's query plaintexts in every column.
var fixtureRankings = []testusers.Ranking{
	{ID: 1, Level: -20, Floor: -30, Points: -5, Total: -9, Speed: -1.25, Pace: -3.5, Score: -2.5, Mean: -0.25, Title: "apple", Handle: "Alice"},
	{ID: 2, Level: 10, Floor: -3, Points: 5_000_000_000, Total: -1, Speed: 2.5, Pace: -0.5, Score: 9.75, Mean: 0, Title: "mango", Handle: "Carol"},
	{ID: 3, Level: 99, Floor: 4, Points: 6_000_000_000, Total: 12, Speed: 8, Pace: 0.75, Score: 100, Mean: 3.5, Title: "Zucchini", Handle: "dave"},
}

// TestV4OrderedRowsMatchTheCommittedFixture checks the committed
// v4_ordered_rows.json against what the generated code seals today, as
// TestV4RowsMatchTheCommittedFixture does for v4_rows.json: everything but
// each `c` must match, and the committed `c` values must open.
// EQL_UPDATE_FIXTURES rewrites the file when something other than the
// ciphertexts moved.
func TestV4OrderedRowsMatchTheCommittedFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	encrypted, err := testusers.EncryptRanking(ctx, c.DefaultKeyset(), fixtureRankings)
	if err != nil {
		t.Fatal(err)
	}
	fixture := orderedRowsFixture{
		Comment: "Ranking rows sealed by the Go SDK's generated code over the deterministic EQL guest with the seed below; the Rust suite opens and compares them. Regenerate with EQL_UPDATE_FIXTURES=1 go test ./encrypt -run TestV4OrderedRows, do not edit.",
		Seed:    string(testSeed[:]),
		Table:   "rankings",
	}
	for i, e := range encrypted {
		row := orderedRow{ID: fixtureRankings[i].ID, Plaintext: orderedPlainOf(fixtureRankings[i]), Stored: map[string]json.RawMessage{}}
		for column, value := range storedRanking(e) {
			row.Stored[column] = json.RawMessage(value)
		}
		fixture.Rows = append(fixture.Rows, row)
	}
	rendered, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := fixturePath("v4_ordered_rows.json")
	var committed orderedRowsFixture
	committedBytes, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(committedBytes, &committed)
	}
	same := err == nil && bytes.Equal(orderedWithoutCiphertexts(t, committed), orderedWithoutCiphertexts(t, fixture))
	if os.Getenv("EQL_UPDATE_FIXTURES") != "" && !same {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: rewritten", path)
		committed, same, err = fixture, true, nil
	}
	if err != nil {
		t.Fatalf("%v: run with EQL_UPDATE_FIXTURES=1 to write it", err)
	}
	if !same {
		t.Errorf("%s differs from what the generated code seals today beyond the ciphertexts; regenerate it with EQL_UPDATE_FIXTURES=1", path)
	}

	// The committed ciphertexts still open, to the committed plaintexts.
	sealed := make([]testusers.EncryptedRanking, len(committed.Rows))
	for i, row := range committed.Rows {
		s := row.Stored
		sealed[i] = testusers.EncryptedRanking{
			ID: row.ID, Level: []byte(s["level"]), Floor: []byte(s["floor"]), Points: []byte(s["points"]), Total: []byte(s["total"]),
			Speed: []byte(s["speed"]), Pace: []byte(s["pace"]), Score: []byte(s["score"]), Mean: []byte(s["mean"]),
			Title: []byte(s["title"]), Handle: []byte(s["handle"]),
		}
	}
	opened, err := testusers.DecryptRanking(ctx, c.DefaultKeyset(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range committed.Rows {
		if got := orderedPlainOf(opened[i]); got != row.Plaintext {
			t.Errorf("row %d opens to %+v, want %+v", row.ID, got, row.Plaintext)
		}
	}
}

// orderedWithoutCiphertexts renders a fixture with every stored value's `c`
// removed: the part of the file that is the same on every run.
func orderedWithoutCiphertexts(t *testing.T, f orderedRowsFixture) []byte {
	t.Helper()
	out := f
	out.Rows = nil
	for _, row := range f.Rows {
		stripped := orderedRow{ID: row.ID, Plaintext: row.Plaintext, Stored: map[string]json.RawMessage{}}
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
