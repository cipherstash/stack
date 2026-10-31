package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

type readDeclaration struct {
	Kind string `json:"kind"`
	Null string `json:"null"`
}
type readCase struct {
	ID           string                        `json:"id"`
	Write        readDeclaration               `json:"write"`
	Read         readDeclaration               `json:"read"`
	ContextField bool                          `json:"context_field"`
	Rows         []map[string]conformanceInput `json:"rows"`
	Mutation     struct {
		Kind string `json:"kind"`
		Row  int    `json:"row"`
	} `json:"mutation"`
	ExpectedContext string            `json:"expected_context"`
	Adapter         bool              `json:"adapter"`
	CheckError      *declarationError `json:"check_error"`
	Expected        struct {
		Stage      string                         `json:"stage"`
		Retrievals int                            `json:"retrievals"`
		Error      *declarationError              `json:"error"`
		Rows       *[]map[string]conformanceInput `json:"rows"`
	} `json:"expected"`
}

func readPlan(d readDeclaration, contextField bool) *record.Plan {
	p := &record.Plan{Context: []string{"conformance"}, Fields: []record.Field{{Name: "value", Kind: record.Kind(d.Kind), Null: record.Null(d.Null), Outputs: []record.Output{record.Ciphertext, record.Equality}}}}
	if contextField {
		p.Context = nil
		p.ContextField = "tenant"
	}
	return p
}

func readTree(stored []record.Sealed, contextField bool) []any {
	batch := make([]any, len(stored))
	for i, row := range stored {
		fields := map[string]any{}
		if contextField {
			fields["tenant"] = map[string]any{"passthrough": vcvalue.Plain{V: row["tenant"].Context}}
		}
		if field, ok := row["value"]; ok {
			fields["value"] = map[string]any{"c": encrypt.Ciphertext(field.Ciphertext), "eq": vcvalue.Plain{V: field.Terms[record.Equality]}}
		}
		batch[i] = fields
	}
	return batch
}

func mutateRead(t *testing.T, batch []any, c readCase) {
	t.Helper()
	i := c.Mutation.Row
	if i < 0 || i >= len(batch) {
		t.Fatal("mutation row out of range")
	}
	plain := vcvalue.Plain{V: int32(34)}
	if c.Mutation.Kind == "row_plain" {
		batch[i] = plain
		return
	}
	fields := batch[i].(map[string]any)
	switch c.Mutation.Kind {
	case "none":
	case "drop_value":
		delete(fields, "value")
	case "field_plain":
		fields["value"] = plain
	case "extra_field":
		fields["extra"] = plain
	case "drop_tenant":
		delete(fields, "tenant")
	case "tenant_no_payload":
		fields["tenant"] = map[string]any{}
	case "tenant_number":
		fields["tenant"].(map[string]any)["passthrough"] = plain
	default:
		outputs := fields["value"].(map[string]any)
		switch c.Mutation.Kind {
		case "drop_c":
			delete(outputs, "c")
		case "drop_eq":
			delete(outputs, "eq")
		case "c_plain":
			outputs["c"] = plain
		case "extra_output":
			outputs["extra"] = plain
		default:
			t.Fatalf("unknown mutation %q", c.Mutation.Kind)
		}
	}
}

func readRefusal(t *testing.T, err error, want *declarationError) {
	t.Helper()
	sentinel := encrypt.ErrEncoding
	if want.Code == "stack_encrypt::context_mismatch" {
		sentinel = encrypt.ErrContextMismatch
	}
	var diagnostic *encrypt.Diagnostic
	if !errors.Is(err, sentinel) || !errors.As(err, &diagnostic) {
		t.Fatalf("expected %s diagnostic, got %v", want.Code, err)
	}
	// Diagnostic counters are JSON numbers; transport decodes them as uint64.
	actualFields, marshalErr := json.Marshal(diagnostic.Fields)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	expectedFields, marshalErr := json.Marshal(want.Fields)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if diagnostic.Code != want.Code || !bytes.Equal(actualFields, expectedFields) {
		t.Fatalf("got %s %#v; want %s %#v", diagnostic.Code, diagnostic.Fields, want.Code, want.Fields)
	}
}

func openedRows(t *testing.T, output any) []record.Source {
	t.Helper()
	batch, ok := output.([]any)
	if !ok {
		t.Fatalf("unexpected opened batch %T", output)
	}
	result := make([]record.Source, len(batch))
	for i, v := range batch {
		fields, ok := v.(vcvalue.Object)
		if !ok {
			t.Fatalf("unexpected opened row %T", v)
		}
		result[i] = record.Source{}
		for _, f := range fields {
			if _, ok := result[i][f.Key]; ok {
				t.Fatal("duplicate opened field")
			}
			result[i][f.Key] = f.Value
		}
	}
	return result
}

func TestReadConformance(t *testing.T) {
	var corpus struct {
		Version              int        `json:"version"`
		Profile              string     `json:"profile"`
		RequiredCapabilities []string   `json:"required_capabilities"`
		Cases                []readCase `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "reads.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-reads-v1" || len(corpus.Cases) == 0 {
		t.Fatal("unsupported or empty read corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "read-shapes", "authenticated-types", "context-preflight"}) {
		t.Fatal("unsupported required capabilities")
	}
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) && os.Getenv("STACK_CONFORMANCE_REQUIRED") != "1" {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wasm, err := os.ReadFile("testdata/stack_encrypt_guest_deterministic.wasm")
	if err != nil {
		t.Fatal(err)
	}
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checker.Close() })
	cipher := client.DefaultKeyset()
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatal("empty or repeated ID")
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			switch c.Expected.Stage {
			case "success", "shape", "preflight", "authenticated":
			default:
				t.Fatal("unknown stage")
			}
			write, read := readPlan(c.Write, c.ContextField), readPlan(c.Read, c.ContextField)
			stored, err := cipher.Seal(ctx, write, runtimeRows(t, c.Rows))
			if err != nil {
				t.Fatal(err)
			}
			tree := readTree(stored, c.ContextField)
			mutateRead(t, tree, c)
			// Without a cipher, preflight must reject malformed shapes/contexts.
			// Valid shapes (including concealed type mismatches) must reach ErrState.
			_, err = checker.OpenTreeForTest(ctx, tree, read, c.ExpectedContext)
			if c.CheckError != nil {
				readRefusal(t, err, c.CheckError)
			} else if !errors.Is(err, encrypt.ErrState) {
				t.Fatalf("expected state boundary after preflight, got %v", err)
			}
			out, err := cipher.OpenTreeForTest(ctx, tree, read, c.ExpectedContext)
			want := c.Expected.Error
			// The guest runs check_record before constructing the pending opener.
			if c.CheckError != nil {
				want = c.CheckError
			}
			if c.Expected.Stage == "success" {
				if want != nil || c.Expected.Rows == nil {
					t.Fatal("ambiguous success outcome")
				}
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(openedRows(t, out), runtimeRows(t, *c.Expected.Rows)) {
					t.Fatal("typed ordered read differs")
				}
			} else {
				if want == nil || c.Expected.Rows != nil {
					t.Fatal("missing or ambiguous refusal")
				}
				readRefusal(t, err, want)
			}
			if c.Adapter {
				if c.Mutation.Kind != "none" {
					t.Fatal("adapter cases must retain the stored shape")
				}
				reader := cipher
				if c.ExpectedContext != "" {
					reader = cipher.Context(c.ExpectedContext)
				}
				opened, err := reader.Open(ctx, read, stored)
				if want != nil {
					readRefusal(t, err, want)
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(opened, runtimeRows(t, *c.Expected.Rows)) {
						t.Fatal("record adapter read differs")
					}
				}
			}
		})
	}
}
