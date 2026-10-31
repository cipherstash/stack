package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The compiled predicate of a document field (match): the generated Match
// on testusers.Entity's custom field values, which order $.weight and each
// emergency contact's relationship, previous_call_count and age.

// predicateNode is one node of eql_v4.query_json_predicate: an object with
// one key, and, for an and, or or not, its children.
type predicateNode map[string]json.RawMessage

func decodeNode(t *testing.T, raw json.RawMessage) (string, json.RawMessage) {
	t.Helper()
	var node predicateNode
	if err := json.Unmarshal(raw, &node); err != nil || len(node) != 1 {
		t.Fatalf("a node is an object with one key: %s (%v)", raw, err)
	}
	for k, v := range node {
		return k, v
	}
	panic("unreachable")
}

// shape writes a compiled tree with its leaves named by kind:
// and(contains, cmp.lt), and collects the leaves in order.
func shape(t *testing.T, raw json.RawMessage, leaves *[]json.RawMessage) string {
	t.Helper()
	key, value := decodeNode(t, raw)
	switch key {
	case "and", "or":
		var children []json.RawMessage
		if err := json.Unmarshal(value, &children); err != nil {
			t.Fatalf("%s holds a list: %v", key, err)
		}
		parts := make([]string, len(children))
		for i, c := range children {
			parts[i] = shape(t, c, leaves)
		}
		return key + "(" + strings.Join(parts, ", ") + ")"
	case "not":
		return "not(" + shape(t, value, leaves) + ")"
	case "cmp":
		bound, operand := decodeNode(t, value)
		*leaves = append(*leaves, operand)
		return "cmp." + bound
	case "contains", "exists", "elements":
		*leaves = append(*leaves, value)
		return key
	}
	t.Fatalf("unknown node %q", key)
	return ""
}

// sameOperand says two operands are one: the same JSON, save the order of
// a containment needle's selectors (sv) and elements (el), which the engine
// shuffles on every derivation.
func sameOperand(t *testing.T, a, b []byte) bool {
	t.Helper()
	canonical := func(raw []byte) string {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		out, err := json.Marshal(unshuffled(v))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	return canonical(a) == canonical(b)
}

// unshuffled sorts every sv and el list in v by its entries' JSON.
func unshuffled(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			v[k] = unshuffled(child)
			if list, ok := v[k].([]any); ok && (k == "sv" || k == "el") {
				slices.SortFunc(list, func(x, y any) int {
					a, _ := json.Marshal(x)
					b, _ := json.Marshal(y)
					return strings.Compare(string(a), string(b))
				})
			}
		}
		return v
	case []any:
		for i := range v {
			v[i] = unshuffled(v[i])
		}
		return v
	}
	return v
}

func compiled(t *testing.T, q eql.JSONSearchPredicateQuery) (string, []json.RawMessage) {
	t.Helper()
	var leaves []json.RawMessage
	return shape(t, json.RawMessage(q), &leaves), leaves
}

// A compiled predicate is a tree of what the other operators derive on the
// same field: each leaf is the operand its own method gives, and the tree
// is the predicate's boolean shape with the guards that make an absent
// path and a JSON null answer as jsonpath answers them.
func TestMatchCompilesToTheOperandsOfTheOtherOperators(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.EntityFields.CustomFieldValues
	must := func(q []byte, err error) json.RawMessage {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	q, err := f.Match(ctx, cipher, `$."extra"."country" == $val && $."weight" < $max`,
		map[string]any{"val": "nz", "max": 9.5}, encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := q.Value(); err != nil || !strings.HasPrefix(fmt.Sprint(v), `{"and":`) {
		t.Fatalf("Match binds as its JSON: %v", err)
	}
	got, leaves := compiled(t, q)
	// == is the containment needle; < is a node there whose ordering term
	// compares. With no ! above it, it sends no null needle.
	if want := "and(contains, exists, cmp.lt)"; got != want {
		t.Fatalf("the tree is %s, want %s", got, want)
	}
	selector, err := f.At.Weight.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []json.RawMessage{
		must(f.EqAt(ctx, cipher, "$.extra.country", "nz")),
		must(json.Marshal(selector.Selector())),
		must(f.At.Weight.Lt(ctx, cipher, 9.5)),
	} {
		if !sameOperand(t, leaves[i], want) {
			t.Errorf("leaf %d is %s, not its operator's %s", i, leaves[i], want)
		}
	}

	// The other shapes: != is a node there that is not the value; exists
	// is the selector; a filter of one condition is a needle; ! and ||
	// keep their places.
	for _, tc := range []struct {
		predicate string
		vars      any
		want      string
	}{
		{`$.address.postcode != null`, map[string]any{}, "and(exists, not(contains))"},
		{`exists($.address.postcode)`, map[string]any{}, "exists"},
		{`!(exists($.extra.preferred_languages[*] ? (@ == $v)))`, map[string]string{"v": "csharp"}, "not(contains)"},
		{`$.score == 3.14 || !($.weight >= 2)`, map[string]any{}, "or(contains, not(and(exists, not(contains), cmp.gte)))"},
		{`exists($.extra.emergency_contacts[*] ? (@.relationship == $r && @.previous_call_count > $n))`, map[string]any{"r": "Sibling", "n": 5}, "elements"},
		{`$.extra.emergency_contacts[*].age <= 40`, map[string]any{}, "elements"},
	} {
		q, err := f.Match(ctx, cipher, tc.predicate, tc.vars, encrypt.JSONReadOptions{})
		if err != nil {
			t.Fatalf("%s: %v", tc.predicate, err)
		}
		if got, _ := compiled(t, q); got != tc.want {
			t.Errorf("%s compiles to %s, want %s", tc.predicate, got, tc.want)
		}
	}

	// A filter of more than one condition is the element match of the
	// array, read to the same bound.
	opts := encrypt.JSONReadOptions{WildcardBound: 4}
	q, err = f.Match(ctx, cipher, `exists($.extra.emergency_contacts[*] ? (@.relationship == $r && @.previous_call_count > $n))`,
		map[string]any{"r": "Sibling", "n": 5}, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, leaves = compiled(t, q)
	elements := must(f.Elements.ExtraEmergencyContacts.Match(ctx, cipher, opts,
		encrypt.AtPath(testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts.Relationship).Eq("Sibling"),
		encrypt.AtPath(testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts.PreviousCallCount).Gt(5),
	))
	if !sameOperand(t, leaves[0], elements) {
		t.Errorf("the filter is %s, not the element match %s", leaves[0], elements)
	}
}

// vars are any value encoding/json writes as an object: a map, a struct, a
// json.RawMessage of one. Each derives the operand its JSON text does. A
// nil value is what pgx and database/sql bind as SQL NULL, and plaintext
// jsonb_path_match is NULL for every row with NULL vars: Match returns the
// empty operand, which binds as NULL, whatever variables the predicate
// names.
func TestMatchTakesItsVarsAsAnyJSONObject(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.EntityFields.CustomFieldValues
	predicate := `$.extra.country == $val && $.weight < $max`
	derive := func(predicate string, vars any) eql.JSONSearchPredicateQuery {
		t.Helper()
		q, err := f.Match(ctx, cipher, predicate, vars, encrypt.JSONReadOptions{})
		if err != nil {
			t.Fatalf("%T: %v", vars, err)
		}
		return q
	}
	want := derive(predicate, map[string]any{"val": "nz", "max": 9.5})
	type varsStruct struct {
		Val string  `json:"val"`
		Max float64 `json:"max"`
	}
	for _, vars := range []any{
		json.RawMessage(`{"val": "nz", "max": 9.5}`),
		varsStruct{Val: "nz", Max: 9.5},
		&varsStruct{Val: "nz", Max: 9.5},
		map[string]json.RawMessage{"val": json.RawMessage(`"nz"`), "max": json.RawMessage(`9.5`)},
	} {
		if got := derive(predicate, vars); !sameOperand(t, json.RawMessage(got), json.RawMessage(want)) {
			t.Errorf("%T derives another operand", vars)
		}
	}
	// Literals in place of variables derive the same tree with an empty
	// object.
	literal := `$.extra.country == "nz" && $.weight < 9.5`
	if got := derive(literal, map[string]any{}); !sameOperand(t, json.RawMessage(got), json.RawMessage(want)) {
		t.Error("literals derive another operand")
	}
	// A nil value of any kind is SQL NULL: the empty operand, which binds as
	// NULL, for a predicate with variables or without.
	type text string
	var nilMap map[string]any
	var nilStruct *varsStruct
	var nilMapPointer *map[string]any
	var nilString *string
	var nilText *text
	for _, vars := range []any{nil, nilMap, nilStruct, nilMapPointer, nilString, nilText, json.RawMessage(nil), []byte(nil), []any(nil)} {
		for _, p := range []string{predicate, literal} {
			got := derive(p, vars)
			if got != nil {
				t.Errorf("%#v: %s derives an operand, want the empty one", vars, p)
			}
			if v, err := got.Value(); err != nil || v != nil {
				t.Errorf("%#v: the empty operand binds as %v (%v), want NULL", vars, v, err)
			}
		}
	}
}

// What Match refuses, each an *encrypt.Diagnostic wrapping the sentinel
// its status maps to: a grammar refusal is ErrEncoding with its reason,
// the construct in the grammar's words and the byte offset in the
// predicate; an ordering at a path the field does not order is ErrTerm.
// None of them holds a variable's value or the predicate's text.
func TestMatchRefusalsNameTheConstructAndItsOffset(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.EntityFields.CustomFieldValues
	vars := map[string]any{"v": "secret-nz", "flag": true}
	deep := strings.Repeat("(", 33) + "$.a == 1" + strings.Repeat(")", 33)
	for _, tc := range []struct {
		name, predicate string
		vars            any
		reason          string
		construct       string
		at              string // the text the offset points at
	}{
		{"text the grammar does not read", `$.extra.country = $v`, vars, "json_predicate_syntax", "text the grammar does not read", "= $v"},
		{"like_regex", `$.extra.country like_regex "secret"`, vars, "json_predicate_unsupported", "`like_regex`", "like_regex"},
		{"arithmetic", `$.weight + 1 == 2`, vars, "json_predicate_unsupported", "arithmetic (`+`, `-`, `*`, `/`, `%`)", "+ 1"},
		{"a method", `$.weight.size() == 1`, vars, "json_predicate_unsupported", "a method (`.name()`)", ".size()"},
		{"a filter outside exists", `$.extra.preferred_languages[*] ? (@ == $v) == 1`, vars, "json_predicate_unsupported", "a filter outside `exists`", "? (@"},
		{"|| in a filter", `exists($.extra.emergency_contacts[*] ? (@.relationship == $v || @.age > 1))`, vars, "json_predicate_unsupported", "`||` in a filter", "|| @.age"},
		{"an unknown variable", `$.extra.country == $missing`, vars, "json_predicate_unknown_variable", "a variable", "$missing"},
		{"a value an ordering cannot take", `$.weight < $flag`, vars, "json_predicate_value_type", "a value", "$flag"},
		{"an object", `$.extra.country == $obj`, map[string]any{"obj": map[string]any{"secret-nz": 1}}, "json_predicate_value_type", "a value", "$obj"},
		{"!= at a wildcard", `$.extra.preferred_languages[*] != $v`, vars, "json_predicate_not_equal_at_wildcard", "`!=` at a path with a wildcard", "!= $v"},
		{"too deep", deep, nil, "json_predicate_too_deep", "nesting", "$.a"},
		{"a position", `$.extra.preferred_languages[2] == $v`, vars, "json_path_position", "a position (`[2]`)", "[2]"},
		{"a filter with no wildcard", `exists($.address ? (@.postcode == $v))`, vars, "json_path_no_wildcard", "a filter on a path with no wildcard", "$.address ?"},
		{"a wildcard in a member", `exists($.extra.emergency_contacts[*] ? (@.calls[*] == $v))`, vars, "json_path_wildcard", "a wildcard in a filter's member", "@.calls"},
		{"a number JSON cannot hold", `$.weight == 1e999`, vars, "json_syntax", "a value", "1e999"},
	} {
		_, err := f.Match(ctx, cipher, tc.predicate, tc.vars, encrypt.JSONReadOptions{})
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) {
			t.Errorf("%s: %v, want ErrEncoding with a Diagnostic", tc.name, err)
			continue
		}
		want := strings.Index(tc.predicate, tc.at)
		if at, ok := d.At(); d.Reason() != tc.reason || d.Construct() != tc.construct || !ok || at != want {
			t.Errorf("%s: reason %q, construct %q, at %d (%v); want %q, %q, %d: %v", tc.name, d.Reason(), d.Construct(), at, ok, tc.reason, tc.construct, want, err)
		}
		if d.Field() != "custom_field_values" || d.Code != "stack_encrypt::dynamic_predicate" {
			t.Errorf("%s: field %q, code %q", tc.name, d.Field(), d.Code)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), tc.predicate) {
			t.Errorf("%s: the error holds the caller's text: %v", tc.name, err)
		}
	}

	// The input itself: vars that are not an object, or not JSON.
	for _, tc := range []struct {
		name   string
		vars   any
		reason string
	}{
		{"vars that are a list", []string{"secret-nz"}, "json_input"},
		{"vars that are a number", 1, "json_input"},
		{"vars that are not JSON", json.RawMessage(`{"v": "secret-nz"`), "json_syntax"},
		{"vars that are an empty json.RawMessage", json.RawMessage{}, "json_syntax"},
		{"vars that are whitespace", json.RawMessage(" \t\n "), "json_syntax"},
		// Not nil, but the JSON null: not an object, as plaintext refuses it.
		{"vars that are the JSON null", json.RawMessage(`null`), "json_input"},
		{"vars that are the JSON null with space", json.RawMessage(" null\n"), "json_input"},
		{"vars that point to a nil map", func() any { var m map[string]any; return &m }(), "json_input"},
	} {
		_, err := f.Match(ctx, cipher, `$.extra.country == $v`, tc.vars, encrypt.JSONReadOptions{})
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != tc.reason {
			t.Errorf("%s: %v, want ErrEncoding with reason %s", tc.name, err, tc.reason)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the error holds a value: %v", tc.name, err)
		}
	}

	// With nil vars the predicate is still compiled: what the grammar does
	// not read, or the index cannot answer, is refused as plaintext refuses
	// a jsonpath it cannot parse before it reads vars.
	for _, tc := range []struct{ predicate, reason string }{
		{`$.extra.country = $v`, "json_predicate_syntax"},
		{`$.extra.country like_regex "nz"`, "json_predicate_unsupported"},
	} {
		_, err := f.Match(ctx, cipher, tc.predicate, nil, encrypt.JSONReadOptions{})
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != tc.reason {
			t.Errorf("nil vars, %s: %v, want reason %s", tc.predicate, err, tc.reason)
		}
	}

	// An ordering at a path the field does not order is the index's
	// refusal, as the orderings at a path give it.
	for _, predicate := range []string{
		`$.score < 3`,
		`exists($.extra.emergency_contacts[*] ? (@.name == $v && @.age > 1))`,
	} {
		_, err := f.Match(ctx, cipher, predicate, vars, encrypt.JSONReadOptions{})
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrTerm) || !errors.As(err, &d) || d.Code != "stack_encrypt::json_path_not_ordered" {
			t.Errorf("%s: %v, want ErrTerm json_path_not_ordered", predicate, err)
		}
	}

	// Refused before the engine is asked: vars that are a Go string, which
	// writes one JSON string, and no cipher.
	for _, bad := range []any{`{"v": "secret-nz"}`, new(string)} {
		_, err := f.Match(ctx, cipher, `$.extra.country == $v`, bad, encrypt.JSONReadOptions{})
		var d *encrypt.Diagnostic
		if !errors.Is(err, encrypt.ErrEncoding) || errors.As(err, &d) || !strings.Contains(err.Error(), "json.RawMessage") {
			t.Errorf("%T vars: %v, want ErrEncoding from the SDK", bad, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("%T vars: the error holds a value: %v", bad, err)
		}
	}
	if _, err := f.Match(ctx, nil, `$.weight < 1`, nil, encrypt.JSONReadOptions{}); err == nil {
		t.Fatal("Match with no cipher")
	}

	// A bound of 0 is the engine's default through Match, so the engine's
	// own refusal of 0 is reached through QueryTerm alone.
	input := vcvalue.Object{{Key: "predicate", Value: `exists($.a)`}, {Key: "wildcard_bound", Value: uint32(0)}}
	_, err := cipher.QueryTerm(ctx, contactsPlan(), "custom", "match", input)
	var d *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "json_wildcard_bound_zero" {
		t.Errorf("a bound of 0: %v", err)
	}
}

// A compiled predicate is an EQL value: it binds as its JSON, and prints
// and logs as its type and nothing of its terms.
func TestMatchOperandPrintsAndLogsRedacted(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	q, err := testusers.EntityFields.CustomFieldValues.Match(ctx, c.DefaultKeyset(), `$.extra.country == "nz"`, map[string]any{}, encrypt.JSONReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := q.Value(); err != nil || !strings.Contains(fmt.Sprint(v), `"contains"`) {
		t.Fatalf("Value is the JSON: %v", err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("query", "q", q)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		out := fmt.Sprintf(verb, q)
		if out != "eql.JSONSearchPredicateQuery{[redacted]}" {
			t.Errorf("%s prints %s", verb, out)
		}
	}
	if strings.Contains(logged.String(), "contains") || !strings.Contains(logged.String(), `"q":"eql.JSONSearchPredicateQuery{[redacted]}"`) {
		t.Errorf("slog records %s", logged.String())
	}
}
