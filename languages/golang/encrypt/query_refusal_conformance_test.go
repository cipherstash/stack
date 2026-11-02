package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

type refusalFieldSpec struct {
	Kind    string   `json:"kind"`
	Outputs []string `json:"outputs"`
	Null    string   `json:"null"`
}

type refusalCase struct {
	ID            string          `json:"id"`
	Field         string          `json:"field"`
	Operator      string          `json:"operator"`
	Input         json.RawMessage `json:"input"`
	Accepted      *bool           `json:"accepted"`
	ExpectedError *struct {
		Class  string  `json:"class"`
		Code   string  `json:"code"`
		Reason *string `json:"reason"`
		Field  *string `json:"field"`
	} `json:"expected_error"`
	// How the typed Rust chain answers: a native observation this runner
	// parses and does not execute.
	Typed json.RawMessage `json:"typed"`
}

// refusalInput is a scalar input, or for between a list of two: the
// shape the engine reads, as the SDK's QueryTerm takes it.
func refusalInput(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var scalar conformanceInput
	if err := strictUnmarshal(raw, &scalar); err == nil {
		return conformanceValue(t, scalar)
	}
	var list struct {
		Type  string             `json:"type"`
		Items []conformanceInput `json:"items"`
	}
	if err := strictUnmarshal(raw, &list); err != nil || list.Type != "list" {
		t.Fatalf("input is neither a scalar nor a list: %s", raw)
	}
	items := make([]any, len(list.Items))
	for i, item := range list.Items {
		items[i] = conformanceValue(t, item)
	}
	return items
}

func strictUnmarshal(raw json.RawMessage, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func TestQueryRefusalConformance(t *testing.T) {
	var corpus struct {
		Version              int                         `json:"version"`
		Profile              string                      `json:"profile"`
		RequiredCapabilities []string                    `json:"required_capabilities"`
		Fields               map[string]refusalFieldSpec `json:"fields"`
		Cases                []refusalCase               `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "query-refusals.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-query-refusals-v1" || len(corpus.Cases) == 0 || len(corpus.Fields) == 0 {
		t.Fatal("unsupported or empty refusal corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "query-errors", "term-errors"}) {
		t.Fatal("unsupported capabilities")
	}
	names := make([]string, 0, len(corpus.Fields))
	for name := range corpus.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	plan := &record.Plan{Context: []string{"conformance"}}
	for _, name := range names {
		spec := corpus.Fields[name]
		outputs := make([]record.Output, len(spec.Outputs))
		for i, o := range spec.Outputs {
			outputs[i] = record.Output(o)
		}
		plan.Fields = append(plan.Fields, record.Field{Name: name, Kind: record.Kind(spec.Kind), Null: record.Null(spec.Null), Outputs: outputs})
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cipher := client.DefaultKeyset()
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or repeated ID %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			if c.Accepted == nil || *c.Accepted != (c.ExpectedError == nil) {
				t.Fatal("contradictory outcome")
			}
			input := refusalInput(t, c.Input)
			want := c.ExpectedError
			check := func(path string, err error) {
				t.Helper()
				if want == nil {
					if err != nil {
						t.Fatalf("%s: %v", path, err)
					}
					return
				}
				// The binding's sentinel is the class: a source or plan
				// refusal is ErrEncoding, an index's refusal of the value
				// is ErrTerm. The diagnostic code is the same the native
				// engine reports.
				sentinel := encrypt.ErrEncoding
				if want.Class == "term" {
					sentinel = encrypt.ErrTerm
				} else if want.Class != "source" && want.Class != "plan" {
					t.Fatalf("unknown refusal class %q", want.Class)
				}
				var diagnostic *encrypt.Diagnostic
				if !errors.Is(err, sentinel) || !errors.As(err, &diagnostic) {
					t.Fatalf("%s: expected %s diagnostic, got %v", path, want.Code, err)
				}
				if diagnostic.Code != want.Code {
					t.Fatalf("%s: code %s, want %s", path, diagnostic.Code, want.Code)
				}
				if want.Reason != nil && diagnostic.Reason() != *want.Reason {
					t.Fatalf("%s: reason %q, want %q", path, diagnostic.Reason(), *want.Reason)
				}
				if want.Field != nil && diagnostic.Field() != *want.Field {
					t.Fatalf("%s: field %q, want %q", path, diagnostic.Field(), *want.Field)
				}
			}
			_, err := cipher.QueryTerm(ctx, plan, c.Field, c.Operator, input)
			check("QueryTerm", err)
			if c.Operator == "matches" {
				matched, err := cipher.Verify(ctx, plan, c.Field, c.Operator, input, []any{})
				check("Verify", err)
				if err == nil && len(matched) != 0 {
					t.Fatal("an empty page verifies to nothing")
				}
			}
		})
	}
}
