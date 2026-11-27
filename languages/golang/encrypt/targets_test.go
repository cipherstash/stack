package encrypt

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/frame"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// The se_targets entry shape is shared with eql-bindings' serialiser; this
// reader is strict about it, so the next build's entries are read whole or
// refused, never half-read.
func TestParseTargetsReadsEachEntry(t *testing.T) {
	entry := func(fields ...frame.Field) frame.Object { return frame.Object(fields) }
	textEq := entry(
		frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "family", Value: "Text"}, frame.Field{Key: "suffix", Value: "Eq"},
		frame.Field{Key: "plaintext", Value: "string"}, frame.Field{Key: "sql_domain", Value: "eql_v4_text_eq"},
		frame.Field{Key: "indexes", Value: []any{"eq"}}, frame.Field{Key: "query", Value: "TextEqQuery"},
		frame.Field{Key: "query_sql_domain", Value: "eql_v4.query_text_eq"}, frame.Field{Key: "producible", Value: true}, frame.Field{Key: "reason", Value: nil},
		frame.Field{Key: "operators", Value: []any{operator("eq", "exact", "one", "eq")}},
	)
	notYet := entry(
		frame.Field{Key: "name", Value: "JSON"}, frame.Field{Key: "family", Value: "JSON"}, frame.Field{Key: "suffix", Value: ""},
		frame.Field{Key: "plaintext", Value: nil}, frame.Field{Key: "sql_domain", Value: "eql_v4_json"},
		frame.Field{Key: "indexes", Value: []any{"json"}}, frame.Field{Key: "query", Value: nil}, frame.Field{Key: "query_sql_domain", Value: nil},
		frame.Field{Key: "producible", Value: false}, frame.Field{Key: "reason", Value: "the JSON index is a new operation in the engine"},
		frame.Field{Key: "operators", Value: []any{}},
	)
	ordered := entry(
		frame.Field{Key: "name", Value: "IntegerOrdOre"}, frame.Field{Key: "plaintext", Value: "int64"},
		frame.Field{Key: "indexes", Value: []any{"ore"}}, frame.Field{Key: "producible", Value: true},
		frame.Field{Key: "operators", Value: []any{operator("lt", "exact", "one", "ore"), operator("between", "exact", "pair", "ore"), operator("matches", "probabilistic", "one", "match")}},
	)
	got, err := parseTargets(frame.Object{{Key: "targets", Value: []any{textEq, notYet, ordered}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []record.Target{
		{Name: "TextEq", Family: "Text", Suffix: "Eq", Plaintext: record.String, SQLDomain: "eql_v4_text_eq", Indexes: []record.Output{record.Equality}, Query: "TextEqQuery", QuerySQLDomain: "eql_v4.query_text_eq", Producible: true,
			Operators: []record.Operator{{Name: "eq", Fidelity: record.Exact, Index: record.Equality, Input: "value"}}},
		{Name: "JSON", Family: "JSON", Plaintext: record.Untyped, SQLDomain: "eql_v4_json", Indexes: []record.Output{"json"}, Reason: "the JSON index is a new operation in the engine", Operators: []record.Operator{}},
		{Name: "IntegerOrdOre", Plaintext: record.Int64, Indexes: []record.Output{record.Ore}, Producible: true, Operators: []record.Operator{
			{Name: "lt", Fidelity: record.Exact, Index: record.Ore, Input: "value"},
			{Name: "between", Fidelity: record.Exact, Pair: true, Index: record.Ore, Input: "pair"},
			{Name: "matches", Fidelity: record.Probabilistic, Index: record.Match, Input: "value"},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets =\n%+v\nwant\n%+v", got, want)
	}
	empty, err := parseTargets(frame.Object{{Key: "targets", Value: []any{}}})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %v %v", empty, err)
	}
	for name, bad := range map[string]any{
		"not an object":       "targets",
		"another key":         frame.Object{{Key: "types", Value: []any{}}},
		"list not a list":     frame.Object{{Key: "targets", Value: "x"}},
		"entry not object":    frame.Object{{Key: "targets", Value: []any{"TextEq"}}},
		"numeric plaintext":   frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "plaintext", Value: int64(1)}, frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: true})}}},
		"misspelled kind":     frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "plaintext", Value: "strng"}, frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: true})}}},
		"misspelled index":    frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "indexes", Value: []any{"equality"}}, frame.Field{Key: "producible", Value: true})}}},
		"unknown key":         frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "kind", Value: "string"}, frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: true})}}},
		"no name":             frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: true})}}},
		"no producible":       frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "indexes", Value: []any{}})}}},
		"index not string":    frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "indexes", Value: []any{int64(1)}}, frame.Field{Key: "producible", Value: true})}}},
		"producible string":   frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: "yes"})}}},
		"key twice":           frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "A"}, frame.Field{Key: "name", Value: "B"}, frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: true})}}},
		"no operators":        frame.Object{{Key: "targets", Value: []any{entry(frame.Field{Key: "name", Value: "TextEq"}, frame.Field{Key: "indexes", Value: []any{}}, frame.Field{Key: "producible", Value: true})}}},
		"operators not list":  withOperators("eq"),
		"operator not object": withOperators([]any{"eq"}),
		"unknown fidelity":    withOperators([]any{operator("eq", "approximate", "one", "eq")}),
		"unknown arity":       withOperators([]any{operator("eq", "exact", "three", "eq")}),
		"unknown op index":    withOperators([]any{operator("eq", "exact", "one", "equality")}),
		"unknown op input":    withOperators([]any{append(operator("eq", "exact", "one", "eq")[:4], frame.Field{Key: "input", Value: "path_value"})}),
		"no op name":          withOperators([]any{operator("", "exact", "one", "eq")}),
		"unknown operator":    withOperators([]any{operator("like", "exact", "one", "eq")}),
		"operator case":       withOperators([]any{operator("Eq", "exact", "one", "eq")}),
		"op key missing":      withOperators([]any{frame.Object{{Key: "operator", Value: "eq"}}}),
		"op unknown key":      withOperators([]any{append(operator("eq", "exact", "one", "eq"), frame.Field{Key: "case", Value: "insensitive"})}),
		"op key twice":        withOperators([]any{append(operator("eq", "exact", "one", "eq"), frame.Field{Key: "index", Value: "eq"})}),
		"op value not text":   withOperators([]any{frame.Object{{Key: "operator", Value: int64(1)}, {Key: "fidelity", Value: "exact"}, {Key: "arity", Value: "one"}, {Key: "index", Value: "eq"}, {Key: "input", Value: "value"}}}),
	} {
		if _, err := parseTargets(bad); !errors.Is(err, ErrInternal) {
			t.Errorf("%s: %v, want ErrInternal", name, err)
		}
	}
}

// operator is one se_targets operators entry.
func operator(name, fidelity, arity, index string) frame.Object {
	input := "value"
	if arity == "pair" {
		input = "pair"
	}
	return frame.Object{{Key: "operator", Value: name}, {Key: "fidelity", Value: fidelity}, {Key: "arity", Value: arity}, {Key: "index", Value: index}, {Key: "input", Value: input}}
}

// withOperators is a well-formed TextEq entry whose operators are value.
func withOperators(value any) frame.Object {
	return frame.Object{{Key: "targets", Value: []any{frame.Object{
		{Key: "name", Value: "TextEq"}, {Key: "indexes", Value: []any{}}, {Key: "producible", Value: true}, {Key: "operators", Value: value},
	}}}}
}

// se_query_term's object is read with the catalog's own parsers: an
// operator, fidelity or index the catalog would refuse is refused here too,
// and every name the engine writes is read by both.
func TestParseQueryTermTakesOnlyWhatTheEngineWrites(t *testing.T) {
	term := func(operator, fidelity, index string) frame.Object {
		return frame.Object{
			{Key: "operator", Value: operator}, {Key: "fidelity", Value: fidelity}, {Key: "index", Value: index},
			{Key: "domain", Value: nil}, {Key: "encoding", Value: "bytes"}, {Key: "term", Value: []byte{1, 2}},
		}
	}
	for _, name := range []string{"eq", "lt", "lte", "gt", "gte", "between", "matches",
		"contains", "contained_by", "eq_at", "lt_at", "lte_at", "gt_at", "gte_at", "between_at",
		"selector", "subtree", "children", "child_count", "element_match", "match"} {
		got, err := parseQueryTerm(term(name, "exact", "ore"))
		if err != nil || got.Operator != name || got.Fidelity != record.Exact || got.Index != record.Ore {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
		if _, err := parseTargets(withOperators([]any{operator(name, "exact", "one", "ore")})); err != nil {
			t.Errorf("catalog %s: %v", name, err)
		}
	}
	for name, bad := range map[string]frame.Object{
		"unknown operator": term("like", "exact", "eq"),
		"operator case":    term("Eq", "exact", "eq"),
		"unknown fidelity": term("eq", "approximate", "eq"),
		"unknown index":    term("eq", "exact", "jsonb"),
		"misspelled index": term("eq", "exact", "equality"),
	} {
		if _, err := parseQueryTerm(bad); err == nil {
			t.Errorf("%s: read, want refused", name)
		}
	}
}

// The encoding, the term's shape and the domain must agree as the engine
// writes them; a term that mixes them is a wire bug, refused.
func TestParseQueryTermRefusesAMixedShape(t *testing.T) {
	domain := "eql_v4.query_json"
	shaped := func(encoding string, domain any, term any) frame.Object {
		return frame.Object{
			{Key: "operator", Value: "contains"}, {Key: "fidelity", Value: "exact"}, {Key: "index", Value: "json"},
			{Key: "domain", Value: domain}, {Key: "encoding", Value: encoding}, {Key: "term", Value: term},
		}
	}
	for name, ok := range map[string]frame.Object{
		"bytes":       shaped("bytes", nil, []byte{1}),
		"bytes range": shaped("bytes", nil, []any{[]byte{1}, []byte{2}}),
		"eql":         shaped("eql", domain, []byte{1}),
		"eql range":   shaped("eql", domain, []any{[]byte{1}, []byte{2}}),
		"text":        shaped("text", "text", "c2VsZWN0b3I="),
		"text array":  shaped("text_array", "text[]", []any{"dA==", "dQ=="}),
		"no tokens":   shaped("text_array", "text[]", []any{}),
	} {
		if _, err := parseQueryTerm(ok); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]frame.Object{
		"text array as one string": shaped("text_array", "text[]", "dA=="),
		"text as a list":           shaped("text", "text", []any{"dA=="}),
		"eql with no domain":       shaped("eql", nil, []byte{1}),
		"bytes with a domain":      shaped("bytes", domain, []byte{1}),
		"text with no domain":      shaped("text", nil, "dA=="),
		"text array of bytes":      shaped("text_array", "text[]", []any{[]byte{1}, []byte{2}}),
		"eql as text":              shaped("eql", domain, "dA=="),
	} {
		if _, err := parseQueryTerm(bad); err == nil {
			t.Errorf("%s: read, want refused", name)
		}
	}
}
