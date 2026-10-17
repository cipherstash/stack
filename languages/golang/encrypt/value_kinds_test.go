package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// The value-kinds fixture is the cross-language proof for the kinds #1144
// added: packages/stack-encrypt/tests/fixtures/value_kinds.json holds one
// field of each (int8, int16, uint8, uint16, int128, uint128, date,
// timestamp, decimal) sealed by the Rust data-plan lowering under a
// deterministic key source, each value's transport frame, and the equality
// queries vitaminc-normalize folds onto a stored term. The generated
// testusers.ValueKinds — the same context, identities and indexes as tags —
// writes each value as the same frame, opens the Rust record, and derives
// the same term bytes through the guest built over the same source.
// Skipped when the deterministic test build of the guest is absent.

type valueKindsFixture struct {
	KeySource struct {
		Kind string `json:"kind"`
		Seed string `json:"seed"`
	} `json:"key_source"`
	KeysetID string `json:"keyset_id"`
	Values   []struct {
		Field string `json:"field"`
		Frame string `json:"frame"`
		Text  string `json:"text"`
		Type  string `json:"type"`
	} `json:"values"`
	Record  map[string]map[string]json.RawMessage `json:"record"`
	Queries []struct {
		Field    string `json:"field"`
		Frame    string `json:"frame"`
		Operator string `json:"operator"`
		Term     string `json:"term"`
		Text     string `json:"text"`
	} `json:"queries"`
}

func readValueKindsFixture(t *testing.T) valueKindsFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "value_kinds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f valueKindsFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.KeySource.Kind != "deterministic-sha256" || f.KeysetID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("the fixture's key source changed shape: %+v", f.KeySource)
	}
	return f
}

// parseKind reads a fixture value's text as the Go type its field has in
// testusers.ValueKinds.
func parseKind(t *testing.T, field, text string) any {
	t.Helper()
	signed := func(bits int) int64 {
		n, err := strconv.ParseInt(text, 10, bits)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		return n
	}
	unsigned := func(bits int) uint64 {
		n, err := strconv.ParseUint(text, 10, bits)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		return n
	}
	must := func(v any, err error) any {
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		return v
	}
	switch field {
	case "i8":
		return int8(signed(8))
	case "i16":
		return int16(signed(16))
	case "u8":
		return uint8(unsigned(8))
	case "u16":
		return uint16(unsigned(16))
	case "i128":
		return must(encrypt.ParseInt128(text))
	case "u128":
		return must(encrypt.ParseUint128(text))
	case "date":
		d, err := time.Parse(time.DateOnly, text)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		return encrypt.DateOf(d)
	case "at":
		return must(time.Parse(time.RFC3339Nano, text))
	case "amount":
		return must(encrypt.ParseDecimal(text))
	}
	t.Fatalf("the fixture has a field %q the test does not know", field)
	return nil
}

func TestGeneratedCodeOpensTheRustValueKindsFixture(t *testing.T) {
	f := readValueKindsFixture(t)

	// Each value, written by the Go codec, is the frame Rust wrote.
	values := map[string]any{}
	for _, v := range f.Values {
		value := parseKind(t, v.Field, v.Text)
		values[v.Field] = value
		frame, err := vcffi.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", v.Field, err)
		}
		if got := hex.EncodeToString(frame); got != v.Frame {
			t.Errorf("%s (%s): Go writes the frame %s, Rust wrote %s", v.Field, v.Type, got, v.Frame)
		}
	}
	want := testusers.ValueKinds{
		I8:     values["i8"].(int8),
		I16:    values["i16"].(int16),
		U8:     values["u8"].(uint8),
		U16:    values["u16"].(uint16),
		I128:   values["i128"].(encrypt.Int128),
		U128:   values["u128"].(encrypt.Uint128),
		Date:   values["date"].(encrypt.Date),
		At:     values["at"].(time.Time),
		Amount: values["amount"].(encrypt.Decimal),
	}

	seedBytes, err := hex.DecodeString(f.KeySource.Seed)
	if err != nil || len(seedBytes) != 32 {
		t.Fatalf("seed: %v (%d bytes)", err, len(seedBytes))
	}
	c, err := encrypt.NewDeterministicClient(context.Background(), [32]byte(seedBytes))
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) || errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	rec := f.Record
	stored := testusers.EncryptedValueKinds{
		I8:     testusers.EncryptedValueKindsI8{Ciphertext: hexField(t, rec, "i8", "c"), Equality: hexField(t, rec, "i8", "eq"), Ore: hexField(t, rec, "i8", "ore")},
		I16:    testusers.EncryptedValueKindsI16{Ciphertext: hexField(t, rec, "i16", "c"), Equality: hexField(t, rec, "i16", "eq"), Ore: hexField(t, rec, "i16", "ore")},
		U8:     testusers.EncryptedValueKindsU8{Ciphertext: hexField(t, rec, "u8", "c"), Equality: hexField(t, rec, "u8", "eq"), Ore: hexField(t, rec, "u8", "ore")},
		U16:    testusers.EncryptedValueKindsU16{Ciphertext: hexField(t, rec, "u16", "c"), Equality: hexField(t, rec, "u16", "eq"), Ope: hexField(t, rec, "u16", "ope")},
		I128:   testusers.EncryptedValueKindsI128{Ciphertext: hexField(t, rec, "i128", "c"), Equality: hexField(t, rec, "i128", "eq"), Ore: hexField(t, rec, "i128", "ore")},
		U128:   testusers.EncryptedValueKindsU128{Ciphertext: hexField(t, rec, "u128", "c"), Equality: hexField(t, rec, "u128", "eq"), Ope: hexField(t, rec, "u128", "ope")},
		Date:   testusers.EncryptedValueKindsDate{Ciphertext: hexField(t, rec, "date", "c"), Equality: hexField(t, rec, "date", "eq")},
		At:     testusers.EncryptedValueKindsAt{Ciphertext: hexField(t, rec, "at", "c"), Equality: hexField(t, rec, "at", "eq")},
		Amount: testusers.EncryptedValueKindsAmount{Ciphertext: hexField(t, rec, "amount", "c"), Equality: hexField(t, rec, "amount", "eq")},
	}

	same := func(got testusers.ValueKinds) bool {
		at := got.At
		got.At, want.At = time.Time{}, time.Time{}
		defer func() { want.At = values["at"].(time.Time) }()
		return got == want && at.Equal(values["at"].(time.Time))
	}

	// Go opens the record Rust sealed.
	back, err := testusers.DecryptValueKinds(ctx, cipher, []testusers.EncryptedValueKinds{stored})
	if err != nil {
		t.Fatal(err)
	}
	if !same(back[0]) {
		t.Fatalf("DecryptValueKinds = %+v, want %+v", back[0], want)
	}

	// The terms Go derives are the bytes Rust stored.
	fields := testusers.ValueKindsFields
	eqs := map[string]func() (encrypt.EqualityTerm, error){
		"i8":     func() (encrypt.EqualityTerm, error) { return fields.I8.Eq(ctx, cipher, want.I8) },
		"i16":    func() (encrypt.EqualityTerm, error) { return fields.I16.Eq(ctx, cipher, want.I16) },
		"u8":     func() (encrypt.EqualityTerm, error) { return fields.U8.Eq(ctx, cipher, want.U8) },
		"u16":    func() (encrypt.EqualityTerm, error) { return fields.U16.Eq(ctx, cipher, want.U16) },
		"i128":   func() (encrypt.EqualityTerm, error) { return fields.I128.Eq(ctx, cipher, want.I128) },
		"u128":   func() (encrypt.EqualityTerm, error) { return fields.U128.Eq(ctx, cipher, want.U128) },
		"date":   func() (encrypt.EqualityTerm, error) { return fields.Date.Eq(ctx, cipher, want.Date) },
		"at":     func() (encrypt.EqualityTerm, error) { return fields.At.Eq(ctx, cipher, want.At) },
		"amount": func() (encrypt.EqualityTerm, error) { return fields.Amount.Eq(ctx, cipher, want.Amount) },
	}
	for field, eq := range eqs {
		term, err := eq()
		if err != nil || !term.Equal(hexField(t, rec, field, "eq")) {
			t.Errorf("%s equality: %v, equal=%v", field, err, term.Equal(hexField(t, rec, field, "eq")))
		}
	}
	orders := map[string]func() ([]byte, error){
		"i8:ore":   func() ([]byte, error) { return fields.I8.Lt(ctx, cipher, want.I8) },
		"i16:ore":  func() ([]byte, error) { return fields.I16.Lt(ctx, cipher, want.I16) },
		"u8:ore":   func() ([]byte, error) { return fields.U8.Lt(ctx, cipher, want.U8) },
		"u16:ope":  func() ([]byte, error) { return fields.U16.Lt(ctx, cipher, want.U16) },
		"i128:ore": func() ([]byte, error) { return fields.I128.Lt(ctx, cipher, want.I128) },
		"u128:ope": func() ([]byte, error) { return fields.U128.Lt(ctx, cipher, want.U128) },
	}
	for key, order := range orders {
		field, output, _ := bytes.Cut([]byte(key), []byte(":"))
		term, err := order()
		if err != nil || !bytes.Equal(term, hexField(t, rec, string(field), string(output))) {
			t.Errorf("%s: %v, equal=%v", key, err, bytes.Equal(term, hexField(t, rec, string(field), string(output))))
		}
	}

	// A query value that vitaminc-normalize folds onto the stored value —
	// a decimal at another scale, a timestamp truncated to microseconds —
	// derives the stored equality term.
	for _, q := range f.Queries {
		if q.Operator != "eq" {
			t.Fatalf("the fixture has a %s query the test does not know", q.Operator)
		}
		value := parseKind(t, q.Field, q.Text)
		frame, err := vcffi.Marshal(value)
		if err != nil || hex.EncodeToString(frame) != q.Frame {
			t.Errorf("%s query %q: Go writes the frame %x (%v), Rust wrote %s", q.Field, q.Text, frame, err, q.Frame)
		}
		var term encrypt.EqualityTerm
		switch q.Field {
		case "amount":
			term, err = fields.Amount.Eq(ctx, cipher, value.(encrypt.Decimal))
		case "at":
			term, err = fields.At.Eq(ctx, cipher, value.(time.Time))
		default:
			t.Fatalf("the fixture has a query on %q the test does not know", q.Field)
		}
		wantTerm, _ := hex.DecodeString(q.Term)
		if err != nil || !term.Equal(wantTerm) || !term.Equal(hexField(t, rec, q.Field, "eq")) {
			t.Errorf("%s query %q: %v, equal=%v", q.Field, q.Text, err, term.Equal(wantTerm))
		}
	}

	// A Go record of the same values seals, opens, and stores the same
	// terms Rust did.
	again, err := testusers.EncryptValueKinds(ctx, cipher, []testusers.ValueKinds{want})
	if err != nil {
		t.Fatal(err)
	}
	// Every term of every field, against the fixture's record: the
	// ciphertexts differ (each leaf has a fresh nonce), the terms must not.
	goTerms := valueKindsTerms(again[0])
	for field, outputs := range rec {
		for output := range outputs {
			if output == "c" {
				continue
			}
			got, ok := goTerms[field][output]
			if !ok {
				t.Errorf("the Go record has no %s.%s", field, output)
				continue
			}
			if !bytes.Equal(got, hexField(t, rec, field, output)) {
				t.Errorf("%s.%s: the Go record's term is not the one Rust stored", field, output)
			}
		}
	}
	for field, outputs := range goTerms {
		for output := range outputs {
			if _, ok := rec[field][output]; !ok {
				t.Errorf("the Go record has %s.%s, which the fixture does not", field, output)
			}
		}
	}
	opened, err := testusers.DecryptValueKinds(ctx, c, again)
	if err != nil {
		t.Fatal(err)
	}
	if !same(opened[0]) {
		t.Fatalf("a Go record opened as %+v, want %+v", opened[0], want)
	}

	// A leaf moved under another field's label does not open.
	moved := stored
	moved.Date.Ciphertext = stored.Amount.Ciphertext
	if _, err := testusers.DecryptValueKinds(ctx, cipher, []testusers.EncryptedValueKinds{moved}); err == nil {
		t.Error("a leaf opened under another field's label")
	}
}

// valueKindsTerms is each field's terms in a sealed ValueKinds record, by the
// fixture's output names.
func valueKindsTerms(e testusers.EncryptedValueKinds) map[string]map[string][]byte {
	return map[string]map[string][]byte{
		"i8":     {"eq": e.I8.Equality, "ore": e.I8.Ore},
		"i16":    {"eq": e.I16.Equality, "ore": e.I16.Ore},
		"u8":     {"eq": e.U8.Equality, "ore": e.U8.Ore},
		"u16":    {"eq": e.U16.Equality, "ope": e.U16.Ope},
		"i128":   {"eq": e.I128.Equality, "ore": e.I128.Ore},
		"u128":   {"eq": e.U128.Equality, "ope": e.U128.Ope},
		"date":   {"eq": e.Date.Equality},
		"at":     {"eq": e.At.Equality},
		"amount": {"eq": e.Amount.Equality},
	}
}
