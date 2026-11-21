package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The smallint EQL v4 types, sealed through generated code over the
// deterministic guest build with the EQL types: an int16 field reaches
// Smallint and SmallintEq, opens back, and its Eq query is the one
// eql-bindings' own dispatch derives (v4_queries.json, key tally).
func TestV4SmallintFieldsSealAndOpenBack(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	tallies := []testusers.Tally{
		{ID: 1, Small: math.MinInt16, Count: -12, Wide: 7},
		{ID: 2, Small: math.MaxInt16, Count: 0, Wide: math.MinInt16},
	}
	encrypted, err := testusers.EncryptTally(ctx, cipher, tallies)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		for column, value := range map[string][]byte{"small": e.Small, "tally": e.Count, "wide": e.Wide} {
			want := "c,hm,i,v"
			if column == "small" {
				want = "c,i,v"
			}
			if got := keysOf(t, column, value); got != want {
				t.Errorf("row %d %s: keys %s, want %s", i, column, got, want)
			}
		}
	}
	decrypted, err := testusers.DecryptTally(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range tallies {
		if decrypted[i] != tallies[i] {
			t.Errorf("row %d: %+v, want %+v", i, decrypted[i], tallies[i])
		}
	}

	// An int32 field in a smallint type seals at 16 bits: a value that does
	// not fit is refused, not truncated, on every path, and the error names
	// the field. Both bounds, as widened_test.go pins them for IntegerEq.
	for _, v := range []int32{math.MaxInt16 + 1, math.MinInt16 - 1} {
		refusals := map[string]error{}
		_, refusals["EncryptTally"] = testusers.EncryptTally(ctx, cipher, []testusers.Tally{{ID: 3, Wide: v}})
		_, refusals["Wide.Encrypt"] = testusers.TallyFields.Wide.Encrypt(ctx, cipher, v)
		_, refusals["Wide.Eq"] = testusers.TallyFields.Wide.Eq(ctx, cipher, v)
		for path, err := range refusals {
			if !errors.Is(err, encrypt.ErrEncoding) {
				t.Errorf("%s(%d): %v, want ErrEncoding", path, v, err)
			} else if !strings.Contains(err.Error(), "wide") {
				t.Errorf("%s(%d): %v, want the field named", path, v, err)
			}
		}
	}
	// The bounds themselves fit.
	for _, v := range []int32{math.MaxInt16, math.MinInt16} {
		if _, err := testusers.TallyFields.Wide.Eq(ctx, cipher, v); err != nil {
			t.Errorf("Wide.Eq(%d): %v", v, err)
		}
	}

	raw, err := os.ReadFile(fixturePath("v4_queries.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Tally struct {
			Plaintext int16
			Query     string
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	q, err := testusers.TallyFields.Count.Eq(ctx, cipher, fixture.Tally.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Tally.Query == "" || string(q) != fixture.Tally.Query {
		t.Errorf("Count.Eq = %s\nwant       %s", q, fixture.Tally.Query)
	}
}

// tallyRows are the rows v4_smallint_rows.json holds: both extremes of the
// width, and an int32 field at the extremes too.
var tallyRows = []testusers.Tally{
	{ID: 1, Small: math.MinInt16, Count: -12, Wide: math.MinInt16},
	{ID: 2, Small: math.MaxInt16, Count: 7, Wide: math.MaxInt16},
	{ID: 3, Small: 0, Count: -12, Wide: -1},
}

type smallintRowsFixture struct {
	Comment string        `json:"_comment"`
	Seed    string        `json:"seed"`
	Table   string        `json:"table"`
	Rows    []smallintRow `json:"rows"`
}

type smallintRow struct {
	ID        int64                      `json:"id"`
	Plaintext smallintPlain              `json:"plaintext"`
	Stored    map[string]json.RawMessage `json:"stored"`
}

type smallintPlain struct {
	Small int16 `json:"small"`
	Tally int16 `json:"tally"`
	Wide  int32 `json:"wide"`
}

func storedTally(e testusers.EncryptedTally) map[string][]byte {
	return map[string][]byte{"small": e.Small, "tally": e.Count, "wide": e.Wide}
}

// TestV4SmallintRowsMatchTheCommittedFixture checks the committed
// v4_smallint_rows.json against what the generated code seals today, as
// TestV4RowsMatchTheCommittedFixture does for v4_rows.json: everything but
// each `c` must match, and the committed `c` values must open.
// EQL_UPDATE_FIXTURES rewrites the file when something other than the
// ciphertexts moved, so a change that moves only `c` leaves the committed
// file as it was. EQL_V4_SMALLINT_ROWS_OUT names a file to write today's
// rows to, ciphertexts and all: CI hands it to the Rust suite
// (EQL_V4_SMALLINT_ROWS), so Rust opens the smallint ciphertexts the Go SDK
// seals now, not only the committed ones.
func TestV4SmallintRowsMatchTheCommittedFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	encrypted, err := testusers.EncryptTally(ctx, c.DefaultKeyset(), tallyRows)
	if err != nil {
		t.Fatal(err)
	}
	fixture := smallintRowsFixture{
		Comment: "Tally rows sealed by the Go SDK's generated code over the deterministic EQL guest with the seed below; the Rust suite opens and queries them. Regenerate with EQL_UPDATE_FIXTURES=1 go test ./encrypt -run TestV4SmallintRows, do not edit.",
		Seed:    string(testSeed[:]),
		Table:   "profiles",
	}
	for i, e := range encrypted {
		r := tallyRows[i]
		row := smallintRow{ID: r.ID, Plaintext: smallintPlain{r.Small, r.Count, r.Wide}, Stored: map[string]json.RawMessage{}}
		for column, value := range storedTally(e) {
			row.Stored[column] = json.RawMessage(value)
		}
		fixture.Rows = append(fixture.Rows, row)
	}
	rendered, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	if out := os.Getenv("EQL_V4_SMALLINT_ROWS_OUT"); out != "" {
		if err := os.WriteFile(out, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := fixturePath("v4_smallint_rows.json")
	var committed smallintRowsFixture
	committedBytes, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(committedBytes, &committed)
	}
	same := err == nil && bytes.Equal(smallintWithoutCiphertexts(t, committed), smallintWithoutCiphertexts(t, fixture))
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

	sealed := make([]testusers.EncryptedTally, len(committed.Rows))
	for i, row := range committed.Rows {
		sealed[i] = testusers.EncryptedTally{ID: row.ID, Small: []byte(row.Stored["small"]), Count: []byte(row.Stored["tally"]), Wide: []byte(row.Stored["wide"])}
	}
	opened, err := testusers.DecryptTally(ctx, c.DefaultKeyset(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range committed.Rows {
		if got := (smallintPlain{opened[i].Small, opened[i].Count, opened[i].Wide}); got != row.Plaintext {
			t.Errorf("row %d opens to %+v, want %+v", row.ID, got, row.Plaintext)
		}
	}
}

func smallintWithoutCiphertexts(t *testing.T, f smallintRowsFixture) []byte {
	t.Helper()
	out := f
	out.Rows = nil
	for _, row := range f.Rows {
		stripped := smallintRow{ID: row.ID, Plaintext: row.Plaintext, Stored: map[string]json.RawMessage{}}
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
