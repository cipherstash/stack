package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// An encrypted JSON document (the EQL type JsonSearch) through the guest
// that holds the EQL types: a field of kind json names the target with the
// JSON index's options, crosses as its JSON text, and opens back to it.

func jsonPlan() *record.Plan {
	return &record.Plan{Context: []string{"users"}, Fields: []record.Field{{
		Name: "profile", Kind: record.JSON, Target: "JsonSearch", Null: record.SQLNull,
		TargetOptions: &record.TargetOptions{Ordered: []string{"$.age"}},
	}}}
}

func TestJSONDocumentsRoundTripThroughTheGuest(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	jsonDocuments := jsonConformanceCases(t).Documents
	rows := make([]record.Source, len(jsonDocuments))
	for i, doc := range jsonDocuments {
		rows[i] = record.Source{"profile": []byte(doc)}
	}
	sealed, err := c.DefaultKeyset().Seal(ctx, jsonPlan(), rows)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range sealed {
		var stored struct {
			V  int               `json:"v"`
			I  map[string]string `json:"i"`
			H  string            `json:"h"`
			SV []json.RawMessage `json:"sv"`
		}
		if err := json.Unmarshal(s["profile"].EQL, &stored); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		if stored.V != 4 || stored.I["t"] != "users" || stored.I["c"] != "profile" || stored.H == "" || len(stored.SV) == 0 {
			t.Fatalf("row %d: stored %+v", i, stored)
		}
		// The value scans and binds as the generated EQL type.
		var col eql.JSONSearch
		if err := col.Scan(s["profile"].EQL); err != nil {
			t.Fatalf("row %d: Scan: %v", i, err)
		}
	}
	opened, err := c.Open(ctx, jsonPlan(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range opened {
		text, ok := row["profile"].([]byte)
		if !ok {
			t.Fatalf("row %d opened as %T, not bytes", i, row["profile"])
		}
		// Numbers are compared as their text (UseNumber), so an integer
		// past 2^53 that came back as the nearest float would differ.
		got, err := decodeNumbers(text)
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		want, _ := decodeNumbers([]byte(jsonDocuments[i]))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("row %d: opened %s, want %s", i, text, jsonDocuments[i])
		}
	}
}

// A document sealed for users/profile does not open as another column's:
// the guest opens it under the field's own column and refuses a stored
// value whose envelope names another.
func TestJSONDocumentsDoNotOpenUnderAnotherColumn(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	sealed, err := c.DefaultKeyset().Seal(ctx, jsonPlan(), []record.Source{{"profile": []byte(jsonConformanceCases(t).Documents[0])}})
	if err != nil {
		t.Fatal(err)
	}
	other := jsonPlan()
	other.Fields[0].Identity = "other"
	if _, err := c.Open(ctx, other, sealed); !errors.Is(err, encrypt.ErrContextMismatch) {
		t.Fatalf("a users/profile document opened as users/other: %v", err)
	}
}

// Text that is not a document is refused before anything is sealed, with
// the engine's code and without the text.
func TestJSONTextThatIsNotADocumentIsErrEncoding(t *testing.T) {
	c := deterministicEQLClient(t)
	for _, tc := range jsonConformanceCases(t).InvalidDocuments {
		text, code := tc.Text, tc.Reason
		_, err := c.DefaultKeyset().Seal(context.Background(), jsonPlan(), []record.Source{{"profile": []byte(text)}})
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("%s: %v, want ErrEncoding", text, err)
		}
		var d *encrypt.Diagnostic
		if !errors.As(err, &d) || d.Code != "stack_encrypt::target_json" || d.Reason() != code || d.Field() != "profile" {
			t.Fatalf("%s: diagnostic %+v", text, d)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "9999") {
			t.Fatalf("%s: the error holds the text: %v", text, err)
		}
	}
}

// Every operator a document field answers, through the guest: the engine
// lists them with their inputs, and each derives a term of the encoding and
// SQL type the operator binds as.
func TestJSONOperatorsDeriveTaggedTerms(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	checker, err := encrypt.NewChecker(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = checker.Close() }()
	ops, err := checker.Operators(ctx, jsonPlan(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{}
	for _, op := range ops {
		if op.Index != record.JSONIndex {
			t.Fatalf("%s through %s", op.Name, op.Index)
		}
		inputs[op.Name] = op.Input
	}
	want := map[string]string{
		"contains": "json", "contained_by": "json", "eq_at": "path_json",
		"lt_at": "path_json", "lte_at": "path_json", "gt_at": "path_json", "gte_at": "path_json",
		"between_at": "path_pair", "selector": "path", "subtree": "path_bound",
		"children": "path", "child_count": "path", "element_match": "path_predicates", "match": "predicate",
	}
	if !reflect.DeepEqual(inputs, want) {
		t.Fatalf("operators = %v", inputs)
	}
	type obj = vcvalue.Object
	for _, tc := range []struct {
		op, encoding, domain string
		input                obj
		parts                int
	}{
		{"contains", "eql", "eql_v4.query_json", obj{{Key: "json", Value: []byte(`{"age":34}`)}}, 1},
		{"contained_by", "eql", "eql_v4.query_json", obj{{Key: "json", Value: `{"age":34}`}}, 1},
		{"eq_at", "eql", "eql_v4.query_json", obj{{Key: "path", Value: "$.name"}, {Key: "json", Value: []byte(`"Alice"`)}}, 1},
		{"lt_at", "eql", "eql_v4.query_json_leaf", obj{{Key: "path", Value: "$.age"}, {Key: "json", Value: []byte(`40`)}}, 1},
		{"between_at", "eql", "eql_v4.query_json_leaf", obj{{Key: "path", Value: "$.age"}, {Key: "low", Value: []byte(`18`)}, {Key: "high", Value: []byte(`40`)}}, 2},
		{"selector", "text", "text", obj{{Key: "path", Value: "$.name"}}, 1},
		{"subtree", "text_array", "text[]", obj{{Key: "path", Value: "$.visits[*]"}, {Key: "wildcard_bound", Value: uint32(3)}}, 4},
		{"children", "text", "text", obj{{Key: "path", Value: "$.visits"}}, 1},
		{"child_count", "text", "text", obj{{Key: "path", Value: "$.visits"}}, 1},
	} {
		term, err := cipher.QueryTerm(ctx, jsonPlan(), "profile", tc.op, tc.input)
		if err != nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
		parts := len(term.Terms) + len(term.Text)
		if term.Encoding != tc.encoding || term.Domain != tc.domain || parts != tc.parts || term.Operator != tc.op {
			t.Fatalf("%s: %+v", tc.op, term)
		}
	}
	// A position where the operand is a selector is refused, naming the
	// field and the reason.
	_, err = cipher.QueryTerm(ctx, jsonPlan(), "profile", "selector", obj{{Key: "path", Value: "$.visits[1]"}})
	var d *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &d) || d.Reason() != "json_path_position" || d.Field() != "profile" {
		t.Fatalf("a positional selector: %v", err)
	}
}

// A selector read through the guest: the entry `col -> selector` returns,
// as the SQL grafts it (the document's header and the entry's ordinal),
// opens to the scalar; no entry opens to nothing; and another path's entry
// is refused, since the request names the path and the rows do not.
func TestJSONSelectorReadsOpenAgainstTheirRequest(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	sealed, err := cipher.Seal(ctx, jsonPlan(), []record.Source{{"profile": []byte(`{"name":"Alice","age":34,"visits":[{"at":3}]}`)}})
	if err != nil {
		t.Fatal(err)
	}
	selector := func(path string) string {
		term, err := cipher.QueryTerm(ctx, jsonPlan(), "profile", "selector", vcvalue.Object{{Key: "path", Value: path}})
		if err != nil {
			t.Fatal(err)
		}
		return term.Text[0]
	}
	// col -> selector, as eql_v4.json_tree_graft writes it.
	extract := func(s string) []byte {
		var doc struct {
			H  string                       `json:"h"`
			SV []map[string]json.RawMessage `json:"sv"`
		}
		if err := json.Unmarshal(sealed[0]["profile"].EQL, &doc); err != nil {
			t.Fatal(err)
		}
		for j, entry := range doc.SV {
			var es string
			_ = json.Unmarshal(entry["s"], &es)
			if es == s {
				entry["h"], _ = json.Marshal(doc.H)
				entry["j"], _ = json.Marshal(j)
				out, _ := json.Marshal(entry)
				return out
			}
		}
		t.Fatalf("no entry carries %s", s)
		return nil
	}
	name := extract(selector("$.name"))
	opened, err := cipher.JSONOpen(ctx, jsonPlan(), "profile", vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.name"}}, [][][]byte{{name}, {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 2 || len(opened[0]) != 1 || string(opened[0][0]) != `"Alice"` || len(opened[1]) != 0 {
		t.Fatalf("opened %q", opened)
	}
	// A read through a cipher that has audit metadata opens the same rows:
	// a read asks for data keys, so the guest takes the metadata there.
	audited := cipher.Audit(encrypt.NewAuditMetadata().Text("purpose", "read a profile"))
	opened, err = audited.JSONOpen(ctx, jsonPlan(), "profile", vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.name"}}, [][][]byte{{name}, {}})
	if err != nil || len(opened) != 2 || len(opened[0]) != 1 || string(opened[0][0]) != `"Alice"` {
		t.Fatalf("opened through an audited cipher: %q, %v", opened, err)
	}
	// The read sends the cipher's metadata to the guest. The guest refuses
	// an integer above the largest int64, so a read through a cipher that
	// holds one fails. A read that sent no metadata would succeed. The
	// builder has no method for such an integer, so the test puts it there.
	refused := cipher.AuditUncheckedForTest(map[string]any{"fact": uint64(math.MaxUint64)})
	_, err = refused.JSONOpen(ctx, jsonPlan(), "profile", vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.name"}}, [][][]byte{{name}})
	if !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a read through a cipher with metadata the engine refuses: %v, want ErrEncoding", err)
	}
	_, err = cipher.JSONOpen(ctx, jsonPlan(), "profile", vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.age"}}, [][][]byte{{name}})
	if !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("another path's entry: %v", err)
	}
	// col -> on a container with members returns its entry alone, which
	// commits to children the read does not hold: it does not open, and
	// the refusal is ErrEncoding (a container or an altered entry, the
	// client cannot tell which), never ErrAuthentication.
	visits := extract(selector("$.visits"))
	_, err = cipher.JSONOpen(ctx, jsonPlan(), "profile", vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.visits"}}, [][][]byte{{visits}})
	var d *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrEncoding) || errors.Is(err, encrypt.ErrAuthentication) || !errors.As(err, &d) || d.Code != "stack_encrypt::json_not_a_leaf" {
		t.Fatalf("a container through ->: %v", err)
	}
	// A subtree read's request carries its wildcard bound as Go writes an
	// integer, which the engine reads as its bound: a row with no node at
	// the path opens to no values, and a bound the engine cannot read would
	// be refused as ErrEncoding. (A read past the bound is refused as
	// ErrEncoding too; TestJSONDocumentsQueryAndReadInPostgres reads one
	// from PostgreSQL's own rows.)
	bounded := vcvalue.Object{{Key: "operation", Value: "subtree"}, {Key: "path", Value: "$.visits[*].at"}, {Key: "wildcard_bound", Value: uint32(1)}}
	opened, err = cipher.JSONOpen(ctx, jsonPlan(), "profile", bounded, [][][]byte{{}})
	if err != nil || len(opened) != 1 || len(opened[0]) != 0 {
		t.Fatalf("a bounded subtree read of no rows: %q %v", opened, err)
	}
	unreadable := vcvalue.Object{{Key: "operation", Value: "subtree"}, {Key: "path", Value: "$.visits[*].at"}, {Key: "wildcard_bound", Value: "1"}}
	if _, err := cipher.JSONOpen(ctx, jsonPlan(), "profile", unreadable, [][][]byte{{}}); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a bound that is not an integer: %v", err)
	}
}

// jsonEntry is the entry `col -> selector` returns for a sealed document,
// as eql_v4.json_tree_graft writes it, or nil when no entry of the document
// carries the selector.
func jsonEntry(t *testing.T, document []byte, selector string) []byte {
	t.Helper()
	var doc struct {
		H  string                       `json:"h"`
		SV []map[string]json.RawMessage `json:"sv"`
	}
	if err := json.Unmarshal(document, &doc); err != nil {
		t.Fatal(err)
	}
	for j, entry := range doc.SV {
		var s string
		_ = json.Unmarshal(entry["s"], &s)
		if s == selector {
			entry["h"], _ = json.Marshal(doc.H)
			entry["j"], _ = json.Marshal(j)
			out, _ := json.Marshal(entry)
			return out
		}
	}
	return nil
}

// A JSON document sealed through a cipher with a scope, or with a scope and
// a binding, is found and read under them.
//
// Its selectors derive under the column, then the scope, so a cipher with
// the scope finds its entries, and a cipher with another scope, or none,
// does not. A binding is in no query, and a read derives its selector
// under the scope alone. The entries open under the scope and the binding,
// so a cipher with another binding, or none, finds an entry and does not
// open it.
func TestAJSONDocumentIsFoundAndReadUnderItsScopeAndBinding(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	plain := c.DefaultKeyset()
	tenant := plain.Scope(uint64(7))
	bound := tenant.Bind(uint64(9))
	source := []record.Source{{"profile": []byte(`{"name":"Alice","age":34}`)}}
	request := vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.name"}}
	selector := func(cipher *encrypt.Cipher) string {
		t.Helper()
		term, err := cipher.QueryTerm(ctx, jsonPlan(), "profile", "selector", vcvalue.Object{{Key: "path", Value: "$.name"}})
		if err != nil {
			t.Fatal(err)
		}
		return term.Text[0]
	}
	opens := func(cipher *encrypt.Cipher, entry []byte) error {
		t.Helper()
		opened, err := cipher.JSONOpen(ctx, jsonPlan(), "profile", request, [][][]byte{{entry}})
		if err != nil {
			return err
		}
		if len(opened) != 1 || len(opened[0]) != 1 || string(opened[0][0]) != `"Alice"` {
			t.Fatalf("opened %q", opened)
		}
		return nil
	}

	for _, sealedBy := range []struct {
		name   string
		cipher *encrypt.Cipher
		// The ciphers that find the entry and do not open it.
		closed map[string]*encrypt.Cipher
	}{
		{"a scope", tenant, map[string]*encrypt.Cipher{
			"a binding the document was not sealed under": bound,
		}},
		{"a scope and a binding", bound, map[string]*encrypt.Cipher{
			"another row": tenant.Bind(uint64(10)),
			"no row":      tenant,
		}},
	} {
		t.Run(sealedBy.name, func(t *testing.T) {
			sealed, err := sealedBy.cipher.Seal(ctx, jsonPlan(), source)
			if err != nil {
				t.Fatalf("the cipher did not seal a JSON document: %v", err)
			}
			document := sealed[0]["profile"].EQL
			var stored struct{ I struct{ T, C string } }
			if err := json.Unmarshal(document, &stored); err != nil {
				t.Fatal(err)
			}
			if stored.I.T != "users" || stored.I.C != "profile" {
				t.Errorf("i = %+v, want users/profile and nothing else", stored.I)
			}

			// A read prepared with the scope and no binding opens through the
			// cipher the document was sealed through.
			name := jsonEntry(t, document, selector(tenant))
			if name == nil {
				t.Fatal("the tenant's selector names no entry of the tenant's document")
			}
			if err := opens(sealedBy.cipher, name); err != nil {
				t.Fatalf("the cipher that sealed the document did not open its entry: %v", err)
			}
			for whose, other := range sealedBy.closed {
				if err := opens(other, name); err == nil {
					t.Errorf("%s: the entry opened", whose)
				}
			}
			for whose, other := range map[string]*encrypt.Cipher{
				"another tenant": plain.Scope(uint64(8)),
				"no tenant":      plain,
			} {
				if jsonEntry(t, document, selector(other)) != nil {
					t.Errorf("%s: the selector names an entry of the tenant's document", whose)
				}
				if err := opens(other, name); err == nil {
					t.Errorf("%s: the entry opened", whose)
				}
			}
		})
	}

	// A cipher with a binding prepares a read: its selector and its subtree
	// tokens derive under the scope alone, so they are the tenant's. A query,
	// and a node's token, take no binding.
	if got := selector(bound); got != selector(tenant) {
		t.Errorf("a selector through a cipher with a binding is not the tenant's")
	}
	subtree := func(cipher *encrypt.Cipher) ([]string, error) {
		term, err := cipher.QueryTerm(ctx, jsonPlan(), "profile", "subtree", vcvalue.Object{{Key: "path", Value: "$.name"}})
		return term.Text, err
	}
	boundTokens, err := subtree(bound)
	if err != nil {
		t.Fatalf("a subtree read through a cipher with a binding: %v", err)
	}
	if tenantTokens, err := subtree(tenant); err != nil || !slices.Equal(boundTokens, tenantTokens) {
		t.Errorf("a subtree read's tokens through a cipher with a binding are not the tenant's: %v", err)
	}
	for _, operator := range []string{"children", "child_count", "eq_at"} {
		input := vcvalue.Object{{Key: "path", Value: "$.name"}}
		if operator == "eq_at" {
			input = append(input, vcvalue.Field{Key: "json", Value: []byte(`"Alice"`)})
		}
		if _, err := bound.QueryTerm(ctx, jsonPlan(), "profile", operator, input); !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s through a cipher with a binding: %v, want ErrEncoding", operator, err)
		}
	}
}

// decodeNumbers decodes JSON text with each number kept as its text.
func decodeNumbers(text []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}
