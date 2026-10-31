package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

func mustDecimal(t *testing.T, s string) encrypt.Decimal {
	t.Helper()
	d, err := encrypt.ParseDecimal(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustInstant(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func storedLedger(e testusers.EncryptedLedger) map[string][]byte {
	return map[string][]byte{"opened": e.Opened, "due": e.Due, "created": e.Created, "posted": e.Posted, "total": e.Total, "amount": e.Amount}
}

// sameLedger compares two ledgers as values: instants with Equal, since an
// opened time.Time is in UTC and the original may not be.
func sameLedger(a, b testusers.Ledger) bool {
	return a.ID == b.ID && a.Opened == b.Opened && a.Due == b.Due &&
		a.Created.Equal(b.Created) && a.Posted.Equal(b.Posted) &&
		a.Total == b.Total && a.Amount == b.Amount
}

// The date, timestamp and numeric EQL v4 types, sealed through generated
// code over the deterministic guest build with the EQL types: an
// encrypt.Date, a time.Time and an encrypt.Decimal reach each family's
// storage and equality types, open back, and their Eq queries are the ones
// eql-bindings' own dispatch derives (v4_ledger_queries.json).
func TestV4DateTimestampNumericFieldsSealAndOpenBack(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	east := time.FixedZone("UTC+10", 10*60*60)
	ledgers := []testusers.Ledger{
		{
			ID: 1, Opened: encrypt.Date{Year: 2024, Month: time.February, Day: 29}, Due: encrypt.Date{Year: 1, Month: time.January, Day: 1},
			Created: mustInstant(t, "1969-12-31T23:59:59.999999999Z"), Posted: time.Date(2024, time.March, 1, 9, 0, 0, 1, east),
			Total: mustDecimal(t, "-79228162514264337593543950335"), Amount: mustDecimal(t, "1.50"),
		},
		{
			ID: 2, Opened: encrypt.Date{Year: -262143, Month: time.January, Day: 1}, Due: encrypt.Date{Year: 262142, Month: time.December, Day: 31},
			Created: mustInstant(t, "2024-02-29T12:34:56.123456789Z"), Posted: time.Unix(0, 0),
			Total: mustDecimal(t, "0.0000000000000000000000000001"), Amount: mustDecimal(t, "-0.00"),
		},
	}
	encrypted, err := testusers.EncryptLedger(ctx, cipher, ledgers)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		for column, value := range storedLedger(e) {
			want := "c,hm,i,v"
			if column == "opened" || column == "created" || column == "total" {
				want = "c,i,v"
			}
			if got := keysOf(t, column, value); got != want {
				t.Errorf("row %d %s: keys %s, want %s", i, column, got, want)
			}
		}
	}
	decrypted, err := testusers.DecryptLedger(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ledgers {
		if !sameLedger(decrypted[i], ledgers[i]) {
			t.Errorf("row %d: %+v, want %+v", i, decrypted[i], ledgers[i])
		}
		// An instant opens in UTC, with its nanoseconds.
		if decrypted[i].Posted.Location() != time.UTC || decrypted[i].Posted.Nanosecond() != ledgers[i].Posted.Nanosecond() {
			t.Errorf("row %d: posted opens as %v", i, decrypted[i].Posted)
		}
	}
	// A decimal keeps its scale; a negative zero opens as zero.
	if got := decrypted[0].Amount.String(); got != "1.50" {
		t.Errorf("amount opens as %s, want 1.50", got)
	}
	if got := decrypted[1].Amount.String(); got != "0.00" {
		t.Errorf("amount opens as %s, want 0.00", got)
	}

	// Equality follows the baseline: a decimal's scale is normalised, and
	// an instant keeps the microsecond.
	amount := func(s string) []byte {
		q, err := testusers.LedgerFields.Amount.Eq(ctx, cipher, mustDecimal(t, s))
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	posted := func(v time.Time) []byte {
		q, err := testusers.LedgerFields.Posted.Eq(ctx, cipher, v)
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	if !bytes.Equal(amount("1.5"), amount("1.50")) || bytes.Equal(amount("1.5"), amount("1.51")) {
		t.Error("Amount.Eq does not normalise the scale")
	}
	early := posted(mustInstant(t, "2024-02-29T12:00:00.123456001Z"))
	if !bytes.Equal(early, posted(mustInstant(t, "2024-02-29T12:00:00.123456999Z"))) || bytes.Equal(early, posted(mustInstant(t, "2024-02-29T12:00:00.123457Z"))) {
		t.Error("Posted.Eq does not compare to the microsecond")
	}
	// The instant is compared, not the wall clock: the same instant in two
	// locations is one term.
	if !bytes.Equal(early, posted(time.Date(2024, time.February, 29, 22, 0, 0, 123456001, east))) {
		t.Error("Posted.Eq differs for the same instant in another location")
	}

	// What the engine cannot store is refused on every path, naming the
	// field: a zero Date, a date past the range, an instant past it, and
	// a decimal scale past 28.
	refusals := map[string]error{}
	_, refusals["EncryptLedger zero date"] = testusers.EncryptLedger(ctx, cipher, []testusers.Ledger{{ID: 3, Opened: ledgers[0].Opened, Created: ledgers[0].Created, Posted: ledgers[0].Posted}})
	_, refusals["Due.Encrypt zero"] = testusers.LedgerFields.Due.Encrypt(ctx, cipher, encrypt.Date{})
	_, refusals["Due.Eq past the range"] = testusers.LedgerFields.Due.Eq(ctx, cipher, encrypt.Date{Year: 262143, Month: time.January, Day: 1})
	_, refusals["Posted.Eq past the range"] = testusers.LedgerFields.Posted.Eq(ctx, cipher, time.Date(262143, time.January, 1, 0, 0, 0, 0, time.UTC))
	_, refusals["Amount.Eq scale 29"] = testusers.LedgerFields.Amount.Eq(ctx, cipher, encrypt.Decimal{Scale: 29})
	for path, err := range refusals {
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", path, err)
		}
	}

	raw, err := os.ReadFile(fixturePath("v4_ledger_queries.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Due, Posted, Amount struct {
			Plaintext string
			Query     string
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	queries := map[string]func(string) ([]byte, error){
		"due": func(s string) ([]byte, error) {
			v, err := time.Parse(time.DateOnly, s)
			if err != nil {
				return nil, err
			}
			return testusers.LedgerFields.Due.Eq(ctx, cipher, encrypt.DateOf(v))
		},
		"posted": func(s string) ([]byte, error) {
			return testusers.LedgerFields.Posted.Eq(ctx, cipher, mustInstant(t, s))
		},
		"amount": func(s string) ([]byte, error) {
			return testusers.LedgerFields.Amount.Eq(ctx, cipher, mustDecimal(t, s))
		},
	}
	wants := map[string]struct {
		Plaintext string
		Query     string
	}{"due": fixture.Due, "posted": fixture.Posted, "amount": fixture.Amount}
	for column, derive := range queries {
		want := wants[column]
		got, err := derive(want.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if want.Query == "" || string(got) != want.Query {
			t.Errorf("%s.Eq = %s\nwant       %s", column, got, want.Query)
		}
	}
}

// ledgerRows are the rows v4_ledger_rows.json holds: the range's edges, a
// day, instant and number each of the fixture's queries finds, a value in
// the same microsecond and an amount at another scale, which the queries
// find too, and rows they do not.
func ledgerRows(t *testing.T) []testusers.Ledger {
	return []testusers.Ledger{
		{
			ID: 1, Opened: encrypt.Date{Year: -262143, Month: time.January, Day: 1}, Due: encrypt.Date{Year: 2024, Month: time.February, Day: 29},
			Created: mustInstant(t, "1969-12-31T23:59:59.999999999Z"), Posted: mustInstant(t, "2024-02-29T12:34:56.123456Z"),
			Total: mustDecimal(t, "-79228162514264337593543950335"), Amount: mustDecimal(t, "1.50"),
		},
		{
			ID: 2, Opened: encrypt.Date{Year: 262142, Month: time.December, Day: 31}, Due: encrypt.Date{Year: 2024, Month: time.March, Day: 1},
			Created: mustInstant(t, "2024-02-29T12:34:56.123456789Z"), Posted: mustInstant(t, "2024-02-29T12:34:56.123456999Z"),
			Total: mustDecimal(t, "0.0000000000000000000000000001"), Amount: mustDecimal(t, "1.5"),
		},
		{
			ID: 3, Opened: encrypt.Date{Year: 1970, Month: time.January, Day: 1}, Due: encrypt.Date{Year: 2024, Month: time.February, Day: 29},
			Created: mustInstant(t, "1970-01-01T00:00:00Z"), Posted: mustInstant(t, "2024-02-29T12:34:56.123457Z"),
			Total: mustDecimal(t, "1234.5600"), Amount: mustDecimal(t, "1.51"),
		},
	}
}

type ledgerRowsFixture struct {
	Comment string      `json:"_comment"`
	Seed    string      `json:"seed"`
	Table   string      `json:"table"`
	Rows    []ledgerRow `json:"rows"`
}

type ledgerRow struct {
	ID        int64                      `json:"id"`
	Plaintext ledgerPlain                `json:"plaintext"`
	Stored    map[string]json.RawMessage `json:"stored"`
}

// ledgerPlain is a row's plaintext as text: dates in ISO 8601, instants in
// RFC 3339 with nanoseconds, decimals as fixed-point text with their scale.
type ledgerPlain struct {
	Opened  string `json:"opened"`
	Due     string `json:"due"`
	Created string `json:"created"`
	Posted  string `json:"posted"`
	Total   string `json:"total"`
	Amount  string `json:"amount"`
}

// isoDate is a Date as ISO 8601, with the signed year chrono reads for
// years outside 0000 to 9999.
func isoDate(d encrypt.Date) string {
	switch {
	case d.Year < 0:
		return fmt.Sprintf("-%04d-%02d-%02d", -d.Year, d.Month, d.Day)
	case d.Year > 9999:
		return fmt.Sprintf("+%04d-%02d-%02d", d.Year, d.Month, d.Day)
	}
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
}

func plainLedger(l testusers.Ledger) ledgerPlain {
	return ledgerPlain{
		Opened: isoDate(l.Opened), Due: isoDate(l.Due),
		Created: l.Created.UTC().Format(time.RFC3339Nano), Posted: l.Posted.UTC().Format(time.RFC3339Nano),
		Total: l.Total.String(), Amount: l.Amount.String(),
	}
}

// TestV4LedgerRowsMatchTheCommittedFixture checks the committed
// v4_ledger_rows.json against what the generated code seals today, as
// TestV4RowsMatchTheCommittedFixture does for v4_rows.json: everything but
// each `c` must match, and the committed `c` values must open. The Rust
// suite opens the same rows and stores them in PostgreSQL. EQL_UPDATE_FIXTURES
// rewrites the file when something other than the ciphertexts moved.
func TestV4LedgerRowsMatchTheCommittedFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	rows := ledgerRows(t)
	encrypted, err := testusers.EncryptLedger(ctx, c.DefaultKeyset(), rows)
	if err != nil {
		t.Fatal(err)
	}
	fixture := ledgerRowsFixture{
		Comment: "Ledger rows sealed by the Go SDK's generated code over the deterministic EQL guest with the seed below; the Rust suite opens and queries them. Regenerate with EQL_UPDATE_FIXTURES=1 go test ./encrypt -run TestV4LedgerRows, do not edit.",
		Seed:    string(testSeed[:]),
		Table:   "profiles",
	}
	for i, e := range encrypted {
		row := ledgerRow{ID: rows[i].ID, Plaintext: plainLedger(rows[i]), Stored: map[string]json.RawMessage{}}
		for column, value := range storedLedger(e) {
			row.Stored[column] = json.RawMessage(value)
		}
		fixture.Rows = append(fixture.Rows, row)
	}
	rendered, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := fixturePath("v4_ledger_rows.json")
	var committed ledgerRowsFixture
	committedBytes, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(committedBytes, &committed)
	}
	same := err == nil && bytes.Equal(ledgerWithoutCiphertexts(t, committed), ledgerWithoutCiphertexts(t, fixture))
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

	sealed := make([]testusers.EncryptedLedger, len(committed.Rows))
	for i, row := range committed.Rows {
		s := row.Stored
		sealed[i] = testusers.EncryptedLedger{
			ID: row.ID, Opened: []byte(s["opened"]), Due: []byte(s["due"]), Created: []byte(s["created"]),
			Posted: []byte(s["posted"]), Total: []byte(s["total"]), Amount: []byte(s["amount"]),
		}
	}
	opened, err := testusers.DecryptLedger(ctx, c.DefaultKeyset(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range committed.Rows {
		if got := plainLedger(opened[i]); got != row.Plaintext {
			t.Errorf("row %d opens to %+v, want %+v", row.ID, got, row.Plaintext)
		}
	}
}

func ledgerWithoutCiphertexts(t *testing.T, f ledgerRowsFixture) []byte {
	t.Helper()
	out := f
	out.Rows = nil
	for _, row := range f.Rows {
		stripped := ledgerRow{ID: row.ID, Plaintext: row.Plaintext, Stored: map[string]json.RawMessage{}}
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
