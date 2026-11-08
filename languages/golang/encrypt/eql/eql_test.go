package eql_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
)

func TestTypesTableNamesTheProducibleTypes(t *testing.T) {
	var producible []string
	for _, typ := range eql.Types {
		if typ.Producible {
			producible = append(producible, typ.Name)
			if typ.Reason != "" {
				t.Errorf("%s: a producible type has no reason", typ.Name)
			}
		} else if typ.Reason == "" {
			t.Errorf("%s: an unproducible type has a reason", typ.Name)
		}
	}
	want := []string{
		"Integer", "IntegerEq", "IntegerOrdOre", "IntegerOrd", "IntegerOrdOpe",
		"Smallint", "SmallintEq", "SmallintOrdOre", "SmallintOrd", "SmallintOrdOpe",
		"Bigint", "BigintEq", "BigintOrdOre", "BigintOrd", "BigintOrdOpe",
		"Date", "DateEq", "DateOrdOre", "DateOrd", "DateOrdOpe",
		"Timestamp", "TimestampEq", "TimestampOrdOre", "TimestampOrd", "TimestampOrdOpe",
		"Numeric", "NumericEq", "NumericOrdOre", "NumericOrd", "NumericOrdOpe",
		"Text", "TextEq", "TextMatch", "TextOrdOre", "TextOrd", "TextOrdOpe", "TextSearchOre", "TextSearch",
		"Boolean",
		"Real", "RealEq", "RealOrdOre", "RealOrd", "RealOrdOpe",
		"Double", "DoubleEq", "DoubleOrdOre", "DoubleOrd", "DoubleOrdOpe",
		"JsonSearch",
	}
	if len(producible) != len(want) {
		t.Fatalf("producible = %v, want %v", producible, want)
	}
	for i := range want {
		if producible[i] != want[i] {
			t.Fatalf("producible = %v, want %v", producible, want)
		}
	}
	for name, plaintext := range map[string]string{"Integer": "int32", "IntegerEq": "int32", "IntegerOrdOre": "int32", "TextOrdOre": "string", "IntegerOrd": "int32", "Smallint": "int16", "SmallintEq": "int16", "SmallintOrdOre": "int16", "SmallintOrdOpe": "int16", "Bigint": "int64", "BigintEq": "int64", "BigintOrdOpe": "int64", "Boolean": "bool", "Real": "float32", "RealEq": "float32", "RealOrd": "float32", "Double": "float64", "DoubleEq": "float64", "DoubleOrdOpe": "float64", "TextOrd": "string", "Date": "date", "DateEq": "date", "Timestamp": "timestamp", "TimestampEq": "timestamp", "Numeric": "decimal", "NumericEq": "decimal", "DateOrdOre": "date", "TimestampOrd": "timestamp", "NumericOrdOpe": "decimal"} {
		if typ, ok := eql.Lookup(name); !ok || typ.Plaintext != plaintext {
			t.Errorf("%s: Plaintext = %q, want %q", name, typ.Plaintext, plaintext)
		}
	}
	textEq, ok := eql.Lookup("TextEq")
	if !ok || textEq.GoName != "TextEq" || textEq.Plaintext != "string" || textEq.Query != "TextEqQuery" || textEq.SQLDomain != "public.eql_v4_text_eq" || len(textEq.Indexes) != 1 || textEq.Indexes[0] != "eq" {
		t.Fatalf("TextEq = %+v", textEq)
	}
	if j, ok := eql.Lookup("Json"); !ok || j.GoName != "JSON" {
		t.Fatalf("Json's Go name is JSON: %+v", j)
	}
	if _, ok := eql.Lookup("Nope"); ok {
		t.Fatal("Lookup found a type that does not exist")
	}
}

func TestValuesRoundTripThroughTheDriverAndJSON(t *testing.T) {
	doc := []byte(`{"v":4,"i":{"t":"users","c":"email"},"c":"stack-encrypt:1:AA==","hm":"00"}`)
	v := eql.TextEq(doc)
	value, err := v.Value()
	if err != nil || value != string(doc) {
		t.Fatalf("Value = %v, %v", value, err)
	}
	for _, src := range []any{doc, string(doc)} {
		var scanned eql.TextEq
		if err := scanned.Scan(src); err != nil || string(scanned) != string(doc) {
			t.Fatalf("Scan(%T) = %s, %v", src, scanned, err)
		}
	}
	var scanned eql.TextEq
	if err := scanned.Scan(nil); err == nil {
		t.Fatal("NULL scanned into an EQL value")
	}
	if err := scanned.Scan(42); err == nil {
		t.Fatal("an integer scanned into an EQL value")
	}
	out, err := json.Marshal(struct{ Email eql.TextEq }{v})
	if err != nil || string(out) != `{"Email":`+string(doc)+`}` {
		t.Fatalf("Marshal = %s, %v", out, err)
	}
	var back struct{ Email eql.TextEq }
	if err := json.Unmarshal(out, &back); err != nil || string(back.Email) != string(doc) {
		t.Fatalf("Unmarshal = %s, %v", back.Email, err)
	}
	empty, err := json.Marshal(struct{ Email eql.TextEq }{})
	if err != nil || string(empty) != `{"Email":null}` {
		t.Fatalf("an empty value marshals as null: %s, %v", empty, err)
	}
	if nilValue, err := eql.TextEq(nil).Value(); err != nil || nilValue != nil {
		t.Fatalf("an empty value is NULL: %v, %v", nilValue, err)
	}
	if _, err := eql.TextEq([]byte("not json")).MarshalJSON(); err == nil {
		t.Fatal("bytes that are not JSON marshalled")
	}
	var q eql.TextEqQuery
	if err := json.Unmarshal([]byte("null"), &q); err != nil || q != nil {
		t.Fatalf("null unmarshals to an empty value: %v, %v", q, err)
	}
}

// An EQL value prints and logs its type's name and never its bytes, by
// every verb, through %#v and slog, and inside a struct.
func TestValuesPrintAndLogRedacted(t *testing.T) {
	doc := []byte(`{"v":4,"i":{"t":"users","c":"email"},"c":"stack-encrypt:1:SECRET==","hm":"cafe"}`)
	v := eql.TextEq(doc)
	q := eql.JSONSearchPredicateQuery(`{"contains":{"sv":[{"s":"SECRET"}]}}`)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		for _, c := range []struct {
			value any
			want  string
		}{
			{v, "eql.TextEq{[redacted]}"},
			{q, "eql.JSONSearchPredicateQuery{[redacted]}"},
			{eql.TextEq(nil), "eql.TextEq{}"},
		} {
			if got := fmt.Sprintf(verb, c.value); got != c.want {
				t.Errorf("%s prints %s, want %s", verb, got, c.want)
			}
		}
		if got := fmt.Sprintf(verb, struct{ Email eql.TextEq }{v}); strings.Contains(got, "SECRET") || strings.Contains(strings.ToUpper(got), "5345435245") {
			t.Errorf("%s of a struct prints the value: %s", verb, got)
		}
	}
	if v.String() != "eql.TextEq{[redacted]}" {
		t.Errorf("String %s", v.String())
	}
	// slog records what String gives, the type's name with it.
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("row", "email", v, "q", q, "none", eql.TextEq(nil))
	for _, want := range []string{`"email":"eql.TextEq{[redacted]}"`, `"q":"eql.JSONSearchPredicateQuery{[redacted]}"`, `"none":"eql.TextEq{}"`} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("slog records %s, without %s", logged.String(), want)
		}
	}
	if strings.Contains(logged.String(), "SECRET") {
		t.Errorf("slog records the value: %s", logged.String())
	}
	// The JSON is the value itself, as a conversion, the driver and
	// encoding/json give it.
	if got, err := v.Value(); err != nil || got != string(doc) {
		t.Errorf("Value = %v, %v", got, err)
	}
	if string(v) != string(doc) || !bytes.Equal(json.RawMessage(v), doc) {
		t.Error("a conversion does not give the JSON")
	}
	// Reveal is the named call that prints the JSON, as text through fmt
	// and through slog's handlers.
	if got := v.Reveal(); got != string(doc) {
		t.Errorf("Reveal = %s, want the JSON", got)
	}
	if got := fmt.Sprint(v.Reveal()); got != string(doc) {
		t.Errorf("fmt prints Reveal as %s", got)
	}
	logged.Reset()
	slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})).Debug("row", "email", v.Reveal())
	if !strings.Contains(logged.String(), "SECRET") {
		t.Errorf("slog does not record the revealed JSON: %s", logged.String())
	}
	if eql.TextEq(nil).Reveal() != "" {
		t.Error("an empty value reveals text")
	}
}
