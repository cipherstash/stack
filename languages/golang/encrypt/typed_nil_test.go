package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// A typed nil pointer on the two raw paths. Generated code passes a nil
// pointer through gensupport.Deref, which gives an untyped nil; the two
// paths that take a caller's value as it is are Cipher.Seal with a
// hand-built record.Source and Cipher.QueryTerm's input. There a
// (*int64)(nil) is not == nil, so it is sent, and vcffi, from vitaminc
// e9c3837b on (on main, in no Go tag yet), writes it as a typed null,
// padded to the width of an int64, where it wrote a one-byte null. These
// tests pin what the engine does with it: a typed null is a null to the
// engine, so each path answers a typed nil as it answers an untyped one, on
// a field of every null mode.

// typedNilPlan has one int64 field in each null mode and a timestamp field
// that seals its nulls, so both encodings meet every answer the engine has.
var typedNilPlan = &record.Plan{Context: []string{"typed_nil"}, Fields: []record.Field{
	{Name: "every", Kind: record.Int64, Outputs: []record.Output{record.Ciphertext, record.Equality}},
	{Name: "sealed", Kind: record.Int64, Outputs: []record.Output{record.Ciphertext, record.Equality}, Null: record.SealedNull},
	{Name: "sql", Kind: record.Int64, Outputs: []record.Output{record.Ciphertext, record.Ore}, Null: record.SQLNull},
	{Name: "when", Kind: record.Timestamp, Outputs: []record.Output{record.Ciphertext, record.Equality}, Null: record.SealedNull},
}}

// The pinned vcffi behaviour itself, so the engine tests below are read
// against the bytes that reach it: a nil pointer to a fixed-width type is a
// typed null (tag 0x15, then the type, padded to the type's width), not the
// one-byte null an untyped nil is, and it decodes as nil like every null.
func TestANilFixedWidthPointerMarshalsAsATypedNull(t *testing.T) {
	untyped, err := vcffi.Marshal(nil)
	if err != nil || !bytes.Equal(untyped, []byte{0x00}) {
		t.Fatalf("an untyped nil marshals as %x, %v; want the one-byte null", untyped, err)
	}
	for name, tc := range map[string]struct {
		nilPointer any
		present    any
	}{
		"*int64":     {(*int64)(nil), int64(7)},
		"*float64":   {(*float64)(nil), 1.5},
		"*time.Time": {(*time.Time)(nil), time.Unix(1_700_000_000, 0).UTC()},
	} {
		got, err := vcffi.Marshal(tc.nilPointer)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, untyped) || got[0] != 0x15 {
			t.Fatalf("%s: a nil pointer marshals as %x; want a typed null (tag 0x15)", name, got)
		}
		value, err := vcffi.Marshal(tc.present)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(value) {
			t.Fatalf("%s: the typed null is %d bytes, a value %d; want them as long", name, len(got), len(value))
		}
		back, err := vcffi.Unmarshal(got)
		if err != nil || back != nil {
			t.Fatalf("%s: the typed null decodes as %#v, %v; want nil", name, back, err)
		}
	}
}

// Seal with a hand-built Source: a typed nil seals as the untyped nil does
// on a field of every null mode. Sealed, it is a sealed null, as long as a
// value, with the term every nil shares; sql, it is left out of the record;
// not null, it is refused as a value of the wrong type, the same refusal.
// What it sealed opens as nil, as the untyped nil's does.
func TestSealReadsATypedNilAsANull(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	when := time.Unix(1_700_000_000, 0).UTC()
	rows := []record.Source{
		{"every": int64(1), "sealed": int64(2), "sql": int64(3), "when": when},
		{"every": int64(1), "sealed": nil, "sql": nil, "when": nil},
		{"every": int64(1), "sealed": (*int64)(nil), "sql": (*int64)(nil), "when": (*time.Time)(nil)},
	}
	sealed, err := cipher.Seal(ctx, typedNilPlan, rows)
	if err != nil {
		t.Fatal(err)
	}
	present, untyped, typed := sealed[0], sealed[1], sealed[2]

	// A sealed null: both nils are sealed as long as a value, and they
	// share the equality term, which no value has.
	for _, field := range []string{"sealed", "when"} {
		if len(typed[field].Ciphertext) == 0 || len(typed[field].Ciphertext) != len(untyped[field].Ciphertext) || len(typed[field].Ciphertext) != len(present[field].Ciphertext) {
			t.Fatalf("%s: a typed nil seals to %d bytes, an untyped nil to %d, a value to %d; want all three as long",
				field, len(typed[field].Ciphertext), len(untyped[field].Ciphertext), len(present[field].Ciphertext))
		}
		typedTerm, untypedTerm, presentTerm := typed[field].Terms[record.Equality], untyped[field].Terms[record.Equality], present[field].Terms[record.Equality]
		if len(typedTerm) == 0 || !bytes.Equal(typedTerm, untypedTerm) || bytes.Equal(typedTerm, presentTerm) {
			t.Fatalf("%s: a typed nil's equality term is %x, an untyped nil's %x, a value's %x; want the nils to share one and the value another", field, typedTerm, untypedTerm, presentTerm)
		}
	}
	// A SQL null: a typed nil stores nothing, as an untyped nil does; the
	// host sends the typed one (it is not == nil) and the engine leaves it
	// out.
	for name, rec := range map[string]record.Sealed{"a typed nil": typed, "an untyped nil": untyped} {
		if outputs, ok := rec["sql"]; ok {
			t.Fatalf("%s on a null=sql field stored %+v; want no entry", name, outputs)
		}
	}
	if _, ok := present["sql"]; !ok {
		t.Fatal("a value on a null=sql field is stored")
	}

	// Both open as nil, and the two opened rows are the same row.
	opened, err := cipher.Open(ctx, typedNilPlan, sealed)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"sealed", "sql", "when"} {
		v, ok := opened[2][field]
		if !ok || v != nil {
			t.Fatalf("%s sealed from a typed nil opened as %#v (present %v); want an untyped nil", field, v, ok)
		}
	}
	if !reflect.DeepEqual(opened[1], opened[2]) {
		t.Fatalf("a typed nil opened as %#v, an untyped nil as %#v; want the same row", opened[2], opened[1])
	}
	if got := opened[0]; got["sealed"] != int64(2) || got["sql"] != int64(3) || got["when"] != when {
		t.Fatalf("the values opened as %#v", got)
	}

	// A field every row has refuses a typed nil as it refuses an untyped
	// one: a value that is not of the field's type, named.
	for name, v := range map[string]any{"a typed nil": (*int64)(nil), "an untyped nil": nil} {
		_, err := cipher.Seal(ctx, typedNilPlan, []record.Source{{"every": v, "sealed": int64(2), "sql": int64(3), "when": when}})
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Field() != "every" || d.Reason() != "field_type" {
			t.Fatalf("%s on a field every row has: %v; want ErrEncoding naming \"every\" with reason field_type", name, err)
		}
	}
}

// QueryTerm with a typed nil input: the engine reads it as the null it is.
// On a field that seals its nulls, eq derives the term the stored nils
// share, the same term for a typed and an untyped nil; on any other field,
// or operator, a null is no query, and both nils are refused alike.
func TestQueryTermReadsATypedNilAsANull(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	when := time.Unix(1_700_000_000, 0).UTC()
	sealed, err := cipher.Seal(ctx, typedNilPlan, []record.Source{{"every": int64(1), "sealed": nil, "sql": nil, "when": nil}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field     string
		typedNil  any
		aValue    any
		valueTerm []byte
	}{
		{"sealed", (*int64)(nil), int64(2), nil},
		{"when", (*time.Time)(nil), when, nil},
	} {
		typed, err := cipher.QueryTerm(ctx, typedNilPlan, tc.field, "eq", tc.typedNil)
		if err != nil {
			t.Fatalf("%s eq a typed nil: %v", tc.field, err)
		}
		untyped, err := cipher.QueryTerm(ctx, typedNilPlan, tc.field, "eq", nil)
		if err != nil {
			t.Fatalf("%s eq an untyped nil: %v", tc.field, err)
		}
		if typed.Operator != "eq" || typed.Index != record.Equality || len(typed.Terms) != 1 || !reflect.DeepEqual(typed, untyped) {
			t.Fatalf("%s eq a typed nil = %+v, an untyped nil = %+v; want the same eq term", tc.field, typed, untyped)
		}
		if stored := sealed[0][tc.field].Terms[record.Equality]; !bytes.Equal(typed.Terms[0], stored) {
			t.Fatalf("%s eq a typed nil = %x, the stored nil's term is %x; want the query to find the stored nils", tc.field, typed.Terms[0], stored)
		}
		value, err := cipher.QueryTerm(ctx, typedNilPlan, tc.field, "eq", tc.aValue)
		if err != nil || bytes.Equal(value.Terms[0], typed.Terms[0]) {
			t.Fatalf("%s eq a value: %v, %x; want a term other than the nils'", tc.field, err, value.Terms)
		}
	}
	// Everywhere else a null is no query: on a field every row has and on a
	// field whose nulls are SQL NULL. (A field that seals its nulls answers
	// eq alone, so there is no other operator to put a null under.)
	for name, tc := range map[string]struct {
		field, operator string
		input           any
	}{
		"eq on a field every row has":     {"every", "eq", (*int64)(nil)},
		"lt on a null=sql field":          {"sql", "lt", (*int64)(nil)},
		"the untyped nil, for comparison": {"every", "eq", nil},
	} {
		_, err := cipher.QueryTerm(ctx, typedNilPlan, tc.field, tc.operator, tc.input)
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Field() != tc.field || d.Reason() != "null_query" {
			t.Fatalf("%s: %v; want ErrEncoding naming %q with reason null_query", name, err, tc.field)
		}
	}
}
