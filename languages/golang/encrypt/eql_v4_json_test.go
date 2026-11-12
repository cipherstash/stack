package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The storage-only JSON document, the EQL type Json, sealed through
// generated code over the deterministic guest build with the EQL types:
// testusers.Setting's raw document, its optional preferences of a Go type,
// and its labels, a map. Each is one ciphertext, with no index.

// settingRows are the rows v4_json_rows.json holds: an object, an array
// and a JSON null as raw documents, preferences present and nil, and labels
// with members, empty and nil.
var settingRows = []testusers.Setting{
	{ID: 1, Raw: json.RawMessage(`{"name":"Alice","age":34,"tags":["a","b"],"score":1.5,"big":18446744073709551615}`), Prefs: &testusers.SettingPrefs{Theme: "dark", Beta: true}, Labels: map[string]string{"tier": "gold", "region": "eu"}},
	{ID: 2, Raw: json.RawMessage(`[1, 2.5, null, "é"]`), Labels: map[string]string{}},
	{ID: 3, Raw: json.RawMessage(`null`), Prefs: &testusers.SettingPrefs{}},
}

// storedSetting is each sealed field of an encrypted setting by column. A
// nil document, stored as SQL NULL, has no entry.
func storedSetting(e testusers.EncryptedSetting) map[string][]byte {
	out := map[string][]byte{"raw": e.Raw, "labels": e.Labels}
	if e.Prefs != nil {
		out["prefs"] = *e.Prefs
	}
	return out
}

// sameSetting reports whether a setting opened to the one that was sealed.
// A raw document is compared as a JSON value: it is sealed as values, so
// its text is not promised back byte for byte.
func sameSetting(t *testing.T, got, want testusers.Setting) bool {
	t.Helper()
	return got.ID == want.ID &&
		sameJSON(t, got.Raw, want.Raw) &&
		reflect.DeepEqual(got.Prefs, want.Prefs) &&
		// A nil map is written as a JSON null, and read back as a nil map.
		len(got.Labels) == len(want.Labels) && (len(want.Labels) == 0 || reflect.DeepEqual(got.Labels, want.Labels)) &&
		(got.Labels == nil) == (want.Labels == nil)
}

func TestASettingsDocumentsRoundTrip(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	encrypted, err := testusers.EncryptSetting(ctx, c.DefaultKeyset(), settingRows)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		// A storage-only value is its envelope and one ciphertext: no
		// header, no entries and no term.
		for column, value := range storedSetting(e) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(value, &raw); err != nil {
				t.Fatalf("row %d %s is not JSON: %v", i, column, err)
			}
			keys := make([]string, 0, len(raw))
			for k := range raw {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if got := strings.Join(keys, ","); got != "c,i,v" {
				t.Errorf("row %d %s has the keys %s, want c,i,v", i, column, got)
			}
			var id struct{ T, C string }
			if err := json.Unmarshal(raw["i"], &id); err != nil || id.T != "settings" || id.C != column {
				t.Errorf("row %d %s: i = %s", i, column, raw["i"])
			}
			if string(raw["v"]) != "4" {
				t.Errorf("row %d %s: v = %s, want 4", i, column, raw["v"])
			}
		}
	}
	// A nil document is SQL NULL. A JSON null, and a zero value of a Go
	// type, are documents.
	if encrypted[0].Prefs == nil || encrypted[1].Prefs != nil || encrypted[2].Prefs == nil {
		t.Fatalf("prefs: %v %v %v", encrypted[0].Prefs, encrypted[1].Prefs, encrypted[2].Prefs)
	}
	if s := encrypted[0].String(); strings.Contains(s, "Alice") || strings.Contains(s, "gold") {
		t.Fatalf("String shows a document: %s", s)
	}
	back, err := testusers.DecryptSetting(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range settingRows {
		if !sameSetting(t, back[i], settingRows[i]) {
			t.Errorf("row %d opens to %+v, want %+v", i, back[i], settingRows[i])
		}
	}
	// A document longer by one byte is a ciphertext longer by one byte:
	// nothing is added beside the document's text.
	short, err := testusers.SettingFields.Raw.Encrypt(ctx, c.DefaultKeyset(), json.RawMessage(`{"name":"Ada"}`))
	if err != nil {
		t.Fatal(err)
	}
	long, err := testusers.SettingFields.Raw.Encrypt(ctx, c.DefaultKeyset(), json.RawMessage(`{"name":"Adam"}`))
	if err != nil {
		t.Fatal(err)
	}
	if rawLen(t, long) != rawLen(t, short)+1 {
		t.Errorf("the ciphertexts are %d and %d bytes: one byte of text is one byte of ciphertext", rawLen(t, short), rawLen(t, long))
	}
}

// rawLen is the length of a stored value's sealed leaf, in bytes.
func rawLen(t *testing.T, value eql.JSON) int {
	t.Helper()
	var envelope struct{ C string }
	if err := json.Unmarshal(value, &envelope); err != nil {
		t.Fatal(err)
	}
	body, ok := strings.CutPrefix(envelope.C, "stack-encrypt:1:")
	if !ok {
		t.Fatalf("c = %q", envelope.C)
	}
	// Standard base64 with padding: three bytes for each four characters,
	// less the padding.
	return len(body)/4*3 - strings.Count(body, "=")
}

// A field's entry encrypts one value for an update: the EQL value a row
// holds, which opens through the generated code.
func TestASettingsFieldEntriesEncryptOneValue(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	raw, err := testusers.SettingFields.Raw.Encrypt(ctx, c.DefaultKeyset(), json.RawMessage(`{"a":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	prefs, err := testusers.SettingFields.Prefs.Encrypt(ctx, c.DefaultKeyset(), testusers.SettingPrefs{Theme: "light"})
	if err != nil {
		t.Fatal(err)
	}
	labels, err := testusers.SettingFields.Labels.Encrypt(ctx, c.DefaultKeyset(), map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	back, err := testusers.DecryptSetting(ctx, c, []testusers.EncryptedSetting{{ID: 7, Raw: raw, Prefs: &prefs, Labels: labels}})
	if err != nil {
		t.Fatal(err)
	}
	want := testusers.Setting{ID: 7, Raw: json.RawMessage(`{"a":[1,2]}`), Prefs: &testusers.SettingPrefs{Theme: "light"}, Labels: map[string]string{"k": "v"}}
	if !sameSetting(t, back[0], want) {
		t.Fatalf("opens to %+v, want %+v", back[0], want)
	}
}

// Text that is not a document by the engine's rules is refused when it is
// sealed, and the error shows none of it.
func TestASettingRefusesTextThatIsNotADocument(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	const secret = "s3cret-value"
	for name, raw := range map[string]string{
		"empty":          ``,
		"not JSON":       `{"k": "` + secret + `"`,
		"a repeated key": `{"k": "` + secret + `", "k": 1}`,
		"a wide integer": `18446744073709551616`,
	} {
		_, err := testusers.EncryptSetting(ctx, c.DefaultKeyset(), []testusers.Setting{{ID: 1, Raw: json.RawMessage(raw), Labels: map[string]string{}}})
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error shows the document: %v", name, err)
		}
	}
}

// A stored value that is not a Json document does not open as one: a
// searchable document has another shape, and a text value's ciphertext
// holding text that is not JSON was sealed as another type.
func TestASettingRefusesAStoredValueOfAnotherType(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	customers, err := testusers.EncryptCustomer(ctx, c.DefaultKeyset(), []testusers.Customer{{ID: 1, Profile: json.RawMessage(`{"a":1}`)}})
	if err != nil {
		t.Fatal(err)
	}
	good, err := testusers.EncryptSetting(ctx, c.DefaultKeyset(), settingRows[:1])
	if err != nil {
		t.Fatal(err)
	}
	searchable := good[0]
	searchable.Raw = eql.JSON(customers[0].Profile)
	if _, err := testusers.DecryptSetting(ctx, c, []testusers.EncryptedSetting{searchable}); err == nil {
		t.Error("a JsonSearch value opened as a Json document")
	}
}

type jsonRowsFixture struct {
	Comment string    `json:"_comment"`
	Seed    string    `json:"seed"`
	Table   string    `json:"table"`
	Rows    []jsonRow `json:"rows"`
}

type jsonRow struct {
	ID        int64                      `json:"id"`
	Plaintext jsonPlain                  `json:"plaintext"`
	Stored    map[string]json.RawMessage `json:"stored"`
}

// jsonPlain is a setting's plaintext as the fixture holds it: each
// document as JSON, and nil preferences as an absent member.
type jsonPlain struct {
	Raw    json.RawMessage         `json:"raw"`
	Prefs  *testusers.SettingPrefs `json:"prefs,omitempty"`
	Labels map[string]string       `json:"labels"`
}

func settingOf(id int64, p jsonPlain) testusers.Setting {
	return testusers.Setting{ID: id, Raw: p.Raw, Prefs: p.Prefs, Labels: p.Labels}
}

// jsonFixtureOf is the fixture of rows sealed as encrypted.
func jsonFixtureOf(comment string, rows []testusers.Setting, encrypted []testusers.EncryptedSetting) jsonRowsFixture {
	fixture := jsonRowsFixture{Comment: comment, Seed: string(testSeed[:]), Table: "settings"}
	for i, e := range encrypted {
		r := rows[i]
		row := jsonRow{ID: r.ID, Plaintext: jsonPlain{Raw: r.Raw, Prefs: r.Prefs, Labels: r.Labels}, Stored: map[string]json.RawMessage{}}
		for column, value := range storedSetting(e) {
			row.Stored[column] = json.RawMessage(value)
		}
		fixture.Rows = append(fixture.Rows, row)
	}
	return fixture
}

// jsonRowsOpenToTheirPlaintexts opens every committed ciphertext of rows
// and compares what it opens to with the row's plaintext.
func jsonRowsOpenToTheirPlaintexts(t *testing.T, c *encrypt.Client, rows []jsonRow) {
	t.Helper()
	sealed := make([]testusers.EncryptedSetting, len(rows))
	for i, row := range rows {
		sealed[i] = testusers.EncryptedSetting{ID: row.ID, Raw: eql.JSON(row.Stored["raw"]), Labels: eql.JSON(row.Stored["labels"])}
		if prefs, ok := row.Stored["prefs"]; ok {
			value := eql.JSON(prefs)
			sealed[i].Prefs = &value
		}
	}
	opened, err := testusers.DecryptSetting(context.Background(), c, sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		if !sameSetting(t, opened[i], settingOf(row.ID, row.Plaintext)) {
			t.Errorf("row %d opens to %+v, want %+v", row.ID, opened[i], row.Plaintext)
		}
	}
}

// TestV4JSONRowsMatchTheCommittedFixture checks the committed
// v4_json_rows.json against what the generated code seals today, as
// TestV4RowsMatchTheCommittedFixture does for v4_rows.json: everything but
// each `c` must match, and the committed `c` values must open.
// EQL_UPDATE_FIXTURES rewrites the file when something other than the
// ciphertexts moved, so a change that moves only `c` leaves the committed
// file as it was. EQL_V4_JSON_ROWS_OUT names a file to write today's rows
// to, ciphertexts and all: CI hands it to the Rust suite
// (EQL_V4_JSON_ROWS), so Rust opens the documents the Go SDK seals now, not
// only the committed ones.
func TestV4JSONRowsMatchTheCommittedFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	encrypted, err := testusers.EncryptSetting(ctx, c.DefaultKeyset(), settingRows)
	if err != nil {
		t.Fatal(err)
	}
	fixture := jsonFixtureOf("Setting rows sealed by the Go SDK's generated code over the deterministic EQL guest with the seed below, as the storage-only Json type; the Rust suite opens them. Regenerate with EQL_UPDATE_FIXTURES=1 go test ./encrypt -run TestV4JSONRows, do not edit.", settingRows, encrypted)
	rendered, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	if out := os.Getenv("EQL_V4_JSON_ROWS_OUT"); out != "" {
		if err := os.WriteFile(out, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := fixturePath("v4_json_rows.json")
	var committed jsonRowsFixture
	committedBytes, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(committedBytes, &committed)
	}
	same := err == nil && bytes.Equal(jsonWithoutCiphertexts(t, committed), jsonWithoutCiphertexts(t, fixture))
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
	jsonRowsOpenToTheirPlaintexts(t, c, committed.Rows)
}

// TestFrozenV4JSONRowsStillOpen holds stored_v4_json_rows_v1.json, rows the
// Go SDK stored as the Json type when the type was first produced. Unlike
// v4_json_rows.json it is never regenerated: nothing writes it. Sealing its
// plaintexts today must give the same rows apart from each `c`, and its
// committed `c` values must still open to its plaintexts. A failure here
// means a change broke rows already stored; see the README in that
// directory before touching the file.
func TestFrozenV4JSONRowsStillOpen(t *testing.T) {
	raw, err := os.ReadFile(fixturePath("stored_v4_json_rows_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frozen jsonRowsFixture
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen.Seed != string(testSeed[:]) || frozen.Table != "settings" || len(frozen.Rows) == 0 {
		t.Fatalf("the frozen fixture changed shape: seed %q, table %q, %d rows", frozen.Seed, frozen.Table, len(frozen.Rows))
	}
	c := deterministicEQLClient(t)
	in := make([]testusers.Setting, len(frozen.Rows))
	for i, row := range frozen.Rows {
		in[i] = settingOf(row.ID, row.Plaintext)
	}
	encrypted, err := testusers.EncryptSetting(context.Background(), c.DefaultKeyset(), in)
	if err != nil {
		t.Fatal(err)
	}
	today := jsonFixtureOf(frozen.Comment, in, encrypted)
	if !bytes.Equal(jsonWithoutCiphertexts(t, frozen), jsonWithoutCiphertexts(t, today)) {
		t.Errorf("sealing the frozen rows' plaintexts today stores different envelopes: a change broke stored rows. Do not regenerate stored_v4_json_rows_v1.json")
	}
	jsonRowsOpenToTheirPlaintexts(t, c, frozen.Rows)
}

// jsonWithoutCiphertexts is the fixture with each stored value's `c`
// removed, for comparing everything a fresh seal does not change.
func jsonWithoutCiphertexts(t *testing.T, f jsonRowsFixture) []byte {
	t.Helper()
	out := f
	out.Rows = nil
	for _, row := range f.Rows {
		stripped := jsonRow{ID: row.ID, Plaintext: row.Plaintext, Stored: map[string]json.RawMessage{}}
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
