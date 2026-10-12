package eql_test

import (
	"encoding/json"
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
	want := []string{"Integer", "Bigint", "Text", "TextEq", "TextMatch", "Boolean", "Real", "Double"}
	if len(producible) != len(want) {
		t.Fatalf("producible = %v, want %v", producible, want)
	}
	for i := range want {
		if producible[i] != want[i] {
			t.Fatalf("producible = %v, want %v", producible, want)
		}
	}
	for name, plaintext := range map[string]string{"Integer": "int32", "Bigint": "int64", "Boolean": "bool", "Real": "float32", "Double": "float64"} {
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
