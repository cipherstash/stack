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
		vcvalue.Field{Key: "plaintext", Value: "string"}, vcvalue.Field{Key: "sql_domain", Value: "eql_v4_text_eq"},
		vcvalue.Field{Key: "indexes", Value: []any{"eq"}}, vcvalue.Field{Key: "query", Value: "TextEqQuery"},
		vcvalue.Field{Key: "query_sql_domain", Value: "eql_v4.query_text_eq"}, vcvalue.Field{Key: "producible", Value: true}, vcvalue.Field{Key: "reason", Value: nil},
		vcvalue.Field{Key: "operators", Value: []any{operator("eq", "exact", "one", "eq")}},
	)
	notYet := entry(
		vcvalue.Field{Key: "name", Value: "JSON"}, vcvalue.Field{Key: "family", Value: "JSON"}, vcvalue.Field{Key: "suffix", Value: ""},
		vcvalue.Field{Key: "plaintext", Value: nil}, vcvalue.Field{Key: "sql_domain", Value: "eql_v4_json"},
		vcvalue.Field{Key: "indexes", Value: []any{"json"}}, vcvalue.Field{Key: "query", Value: nil}, vcvalue.Field{Key: "query_sql_domain", Value: nil},
		vcvalue.Field{Key: "producible", Value: false}, vcvalue.Field{Key: "reason", Value: "the JSON index is a new operation in the engine"},
		vcvalue.Field{Key: "operators", Value: []any{}},
	)
	ordered := entry(
		vcvalue.Field{Key: "name", Value: "IntegerOrdOre"}, vcvalue.Field{Key: "plaintext", Value: "int64"},
		vcvalue.Field{Key: "indexes", Value: []any{"ore"}}, vcvalue.Field{Key: "producible", Value: true},
		vcvalue.Field{Key: "operators", Value: []any{operator("lt", "exact", "one", "ore"), operator("between", "exact", "pair", "ore"), operator("matches", "probabilistic", "one", "match")}},
	)
	got, err := parseTargets(vcvalue.Object{{Key: "targets", Value: []any{textEq, notYet, ordered}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []record.Target{
		{Name: "TextEq", Family: "Text", Suffix: "Eq", Plaintext: record.String, SQLDomain: "eql_v4_text_eq", Indexes: []record.Output{record.Equality}, Query: "TextEqQuery", QuerySQLDomain: "eql_v4.query_text_eq", Producible: true,
			Operators: []record.Operator{{Name: "eq", Fidelity: record.Exact, Index: record.Equality}}},
		{Name: "JSON", Family: "JSON", Plaintext: record.Untyped, SQLDomain: "eql_v4_json", Indexes: []record.Output{"json"}, Reason: "the JSON index is a new operation in the engine", Operators: []record.Operator{}},
		{Name: "IntegerOrdOre", Plaintext: record.Int64, Indexes: []record.Output{record.Ore}, Producible: true, Operators: []record.Operator{
			{Name: "lt", Fidelity: record.Exact, Index: record.Ore},
			{Name: "between", Fidelity: record.Exact, Pair: true, Index: record.Ore},
			{Name: "matches", Fidelity: record.Probabilistic, Index: record.Match},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets =\n%+v\nwant\n%+v", got, want)
	}
	empty, err := parseTargets(vcvalue.Object{{Key: "targets", Value: []any{}}})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %v %v", empty, err)
	}
	for name, bad := range map[string]any{
		"not an object":       "targets",
		"another key":         vcvalue.Object{{Key: "types", Value: []any{}}},
		"list not a list":     vcvalue.Object{{Key: "targets", Value: "x"}},
		"entry not object":    vcvalue.Object{{Key: "targets", Value: []any{"TextEq"}}},
		"numeric plaintext":   vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "plaintext", Value: int64(1)}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"misspelled kind":     vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "plaintext", Value: "strng"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"misspelled index":    vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{"equality"}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"unknown key":         vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "kind", Value: "string"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"no name":             vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"no producible":       vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{}})}}},
		"index not string":    vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{int64(1)}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"producible string":   vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: "yes"})}}},
		"key twice":           vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "A"}, vcvalue.Field{Key: "name", Value: "B"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"no operators":        vcvalue.Object{{Key: "targets", Value: []any{entry(vcvalue.Field{Key: "name", Value: "TextEq"}, vcvalue.Field{Key: "indexes", Value: []any{}}, vcvalue.Field{Key: "producible", Value: true})}}},
		"operators not list":  withOperators("eq"),
		"operator not object": withOperators([]any{"eq"}),
		"unknown fidelity":    withOperators([]any{operator("eq", "approximate", "one", "eq")}),
		"unknown arity":       withOperators([]any{operator("eq", "exact", "three", "eq")}),
		"unknown op index":    withOperators([]any{operator("eq", "exact", "one", "json")}),
		"no op name":          withOperators([]any{operator("", "exact", "one", "eq")}),
		"unknown operator":    withOperators([]any{operator("like", "exact", "one", "eq")}),
		"operator case":       withOperators([]any{operator("Eq", "exact", "one", "eq")}),
		"op key missing":      withOperators([]any{vcvalue.Object{{Key: "operator", Value: "eq"}}}),
		"op unknown key":      withOperators([]any{append(operator("eq", "exact", "one", "eq"), vcvalue.Field{Key: "case", Value: "insensitive"})}),
		"op key twice":        withOperators([]any{append(operator("eq", "exact", "one", "eq"), vcvalue.Field{Key: "index", Value: "eq"})}),
		"op value not text":   withOperators([]any{vcvalue.Object{{Key: "operator", Value: int64(1)}, {Key: "fidelity", Value: "exact"}, {Key: "arity", Value: "one"}, {Key: "index", Value: "eq"}}}),
	} {
		if _, err := parseTargets(bad); !errors.Is(err, ErrInternal) {
			t.Errorf("%s: %v, want ErrInternal", name, err)
		}
	}
}

// operator is one se_targets operators entry.
func operator(name, fidelity, arity, index string) vcvalue.Object {
	return vcvalue.Object{{Key: "operator", Value: name}, {Key: "fidelity", Value: fidelity}, {Key: "arity", Value: arity}, {Key: "index", Value: index}}
}

// withOperators is a well-formed TextEq entry whose operators are value.
func withOperators(value any) vcvalue.Object {
	return vcvalue.Object{{Key: "targets", Value: []any{vcvalue.Object{
		{Key: "name", Value: "TextEq"}, {Key: "indexes", Value: []any{}}, {Key: "producible", Value: true}, {Key: "operators", Value: value},
	}}}}
}

// se_query_term's object is read with the catalog's own parsers: an
// operator, fidelity or index the catalog would refuse is refused here too,
// and every name the engine writes is read by both.
func TestParseQueryTermTakesOnlyWhatTheEngineWrites(t *testing.T) {
	term := func(operator, fidelity, index string) vcvalue.Object {
		return vcvalue.Object{
			{Key: "operator", Value: operator}, {Key: "fidelity", Value: fidelity}, {Key: "index", Value: index},
			{Key: "domain", Value: nil}, {Key: "term", Value: []byte{1, 2}},
		}
	}
	for _, name := range []string{"eq", "lt", "lte", "gt", "gte", "between", "matches"} {
		got, err := parseQueryTerm(term(name, "exact", "ore"))
		if err != nil || got.Operator != name || got.Fidelity != record.Exact || got.Index != record.Ore {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
		if _, err := parseTargets(withOperators([]any{operator(name, "exact", "one", "ore")})); err != nil {
			t.Errorf("catalog %s: %v", name, err)
		}
	}
	for name, bad := range map[string]vcvalue.Object{
		"unknown operator": term("like", "exact", "eq"),
		"operator case":    term("Eq", "exact", "eq"),
		"unknown fidelity": term("eq", "approximate", "eq"),
		"unknown index":    term("eq", "exact", "json"),
		"misspelled index": term("eq", "exact", "equality"),
	} {
		if _, err := parseQueryTerm(bad); err == nil {
			t.Errorf("%s: read, want refused", name)
		}
	}
}
