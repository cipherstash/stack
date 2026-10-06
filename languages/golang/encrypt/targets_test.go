package encrypt

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The se_targets entry shape is shared with eql-bindings' serialiser; this
// reader is strict about it, so the next build's entries are read whole or
// refused, never half-read.
func TestParseTargetsReadsEachEntry(t *testing.T) {
	entry := func(fields ...vcvalue.Field) vcvalue.Object { return vcvalue.Object(fields) }
	textEq := entry(
		vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "family", Value: "Text"}, vcvalue.Field{Key: "suffix", Value: "Eq"},
		vcvalue.Field{Key: "plaintext", Value: "string"}, vcvalue.Field{Key: "sql_domain", Value: "eql_v3_text_eq"},
		vcvalue.Field{Key: "indexes", Value: []any{"eq"}}, vcvalue.Field{Key: "query", Value: "TextEqQuery"},
		vcvalue.Field{Key: "query_sql_domain", Value: "eql_v3.query_text_eq"}, vcvalue.Field{Key: "producible", Value: true}, vcvalue.Field{Key: "reason", Value: nil},
	)
	notYet := entry(
		vcvalue.Field{Key: "name", Value: "JSON"}, vcvalue.Field{Key: "family", Value: "JSON"}, vcvalue.Field{Key: "suffix", Value: ""},
		vcvalue.Field{Key: "plaintext", Value: nil}, vcvalue.Field{Key: "sql_domain", Value: "eql_v3_json"},
		vcvalue.Field{Key: "indexes", Value: []any{"json"}}, vcvalue.Field{Key: "query", Value: nil}, vcvalue.Field{Key: "query_sql_domain", Value: nil},
		vcvalue.Field{Key: "producible", Value: false}, vcvalue.Field{Key: "reason", Value: "the JSON index is a new operation in the engine"},
	)
	got, err := parseTargets(vcvalue.Object{{Key: "targets", Value: []any{textEq, notYet}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []record.Target{
		{Name: "TextEq", Family: "Text", Suffix: "Eq", Plaintext: record.String, SQLDomain: "eql_v3_text_eq", Indexes: []record.Output{record.Equality}, Query: "TextEqQuery", QuerySQLDomain: "eql_v3.query_text_eq", Producible: true},
		{Name: "JSON", Family: "JSON", Plaintext: record.Untyped, SQLDomain: "eql_v3_json", Indexes: []record.Output{"json"}, Reason: "the JSON index is a new operation in the engine"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets =\n%+v\nwant\n%+v", got, want)
	}
	empty, err := parseTargets(vcvalue.Object{{Key: "targets", Value: []any{}}})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %v %v", empty, err)
	}
	for name, bad := range map[string]any{
		"not an object":     "targets",
		"another key":       vcvalue.Object{{Key: "types", Value: []any{}}},
		"list not a list":   vcvalue.Object{{Key: "targets", Value: "x"}},
		"entry not object":  vcvalue.Object{{Key: "targets", Value: []any{"TextEq"}}},
		"numeric plaintext": vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "plaintext", Value: int64(1)}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"unknown key":       vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "kind", Value: "string"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"no name":           vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"no producible":     vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{}})}}},
		"index not string":  vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{int64(1)}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"producible string": vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: "yes"})}}},
		"key twice":         vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "A"}, vcvalue.Field{Key: "name", Value: "B"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
	} {
		if _, err := parseTargets(bad); !errors.Is(err, ErrInternal) {
			t.Errorf("%s: %v, want ErrInternal", name, err)
		}
	}
}
