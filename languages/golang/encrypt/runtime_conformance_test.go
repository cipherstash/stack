package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

type runtimeCase struct {
	ID             string                         `json:"id"`
	Operation      string                         `json:"operation"`
	Kind           string                         `json:"kind"`
	Null           string                         `json:"null"`
	Rows           *[]map[string]conformanceInput `json:"rows"`
	ExpectedRows   *[]map[string]conformanceInput `json:"expected_rows"`
	ExpectedStored *[]bool                        `json:"expected_stored"`
	EqualLengths   bool                           `json:"equal_lengths"`
	Input          *conformanceInput              `json:"input"`
	ExpectedValue  *conformanceInput              `json:"expected_value"`
	ExpectedError  *struct {
		GoMessage string `json:"go_message"`
		Code      string `json:"code"`
		Reason    string `json:"reason"`
		Field     string `json:"field"`
	} `json:"expected_error"`
}

func runtimeRows(t *testing.T, input []map[string]conformanceInput) []record.Source {
	t.Helper()
	rows := make([]record.Source, len(input))
	for i, row := range input {
		rows[i] = record.Source{}
		for key, v := range row {
			rows[i][key] = conformanceValue(t, v)
		}
	}
	return rows
}

func runtimeRefusal(t *testing.T, err error, c runtimeCase) {
	t.Helper()
	var diagnostic *encrypt.Diagnostic
	if c.ExpectedError.GoMessage != "" {
		if !errors.Is(err, encrypt.ErrEncoding) || errors.As(err, &diagnostic) || err.Error() != c.ExpectedError.GoMessage {
			t.Fatalf("unexpected host refusal: %v", err)
		}
		return
	}
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &diagnostic) {
		t.Fatalf("expected encoding diagnostic, got %v", err)
	}
	want := c.ExpectedError
	if diagnostic.Code != want.Code || diagnostic.Reason() != want.Reason || diagnostic.Field() != want.Field {
		t.Fatalf("unexpected diagnostic: %s reason=%s field=%s", diagnostic.Code, diagnostic.Reason(), diagnostic.Field())
	}
}

func TestRuntimeConformance(t *testing.T) {
	var corpus struct {
		Version              int           `json:"version"`
		Profile              string        `json:"profile"`
		RequiredCapabilities []string      `json:"required_capabilities"`
		Cases                []runtimeCase `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "runtime.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-runtime-v1" || len(corpus.Cases) == 0 {
		t.Fatal("unsupported or empty runtime corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "equality", "null-policies", "lossless-query-conversion"}) {
		t.Fatal("unsupported capabilities")
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
	cipher := client.DefaultKeyset()
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or repeated ID %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			plan := &record.Plan{Context: []string{"conformance"}, Fields: []record.Field{{Name: "value", Kind: record.Kind(c.Kind), Null: record.Null(c.Null), Outputs: []record.Output{record.Ciphertext, record.Equality}}}}
			switch c.Operation {
			case "seal":
				if c.Rows == nil || c.Input != nil || c.ExpectedValue != nil {
					t.Fatal("invalid seal case")
				}
				sealed, err := cipher.Seal(ctx, plan, runtimeRows(t, *c.Rows))
				if c.ExpectedError != nil {
					if c.ExpectedRows != nil || c.ExpectedStored != nil || c.EqualLengths {
						t.Fatal("ambiguous seal outcome")
					}
					runtimeRefusal(t, err, c)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if c.ExpectedRows == nil || c.ExpectedStored == nil {
					t.Fatal("missing seal outcome")
				}
				expected := runtimeRows(t, *c.ExpectedRows)
				if len(sealed) != len(*c.Rows) || len(expected) != len(sealed) || len(*c.ExpectedStored) != len(sealed) {
					t.Fatal("row count differs")
				}
				length := -1
				for i, row := range sealed {
					stored, present := row["value"]
					if present != (*c.ExpectedStored)[i] {
						t.Fatalf("row %d: stored field presence differs", i)
					}
					if !present {
						if len(row) != 0 {
							t.Fatal("unexpected stored field")
						}
						continue
					}
					if len(row) != 1 || len(stored.Ciphertext) == 0 || len(stored.Terms) != 1 || len(stored.Terms[record.Equality]) == 0 {
						t.Fatal("unexpected outputs")
					}
					if c.EqualLengths {
						if length >= 0 && length != len(stored.Ciphertext) {
							t.Fatal("null and value ciphertext lengths differ")
						}
						length = len(stored.Ciphertext)
					}
					term, err := cipher.QueryTerm(ctx, plan, "value", "eq", expected[i]["value"])
					if err != nil || len(term.Terms) != 1 || !bytes.Equal(term.Terms[0], stored.Terms[record.Equality]) {
						t.Fatalf("stored/query equality mismatch: %v", err)
					}
				}
				opened, err := cipher.Open(ctx, plan, sealed)
				if err != nil {
					t.Fatal(err)
				}
				// Compare rows individually: an empty batch may use a nil slice in Go.
				if len(opened) != len(expected) {
					t.Fatal("opened row count differs")
				}
				for i := range expected {
					if !reflect.DeepEqual(opened[i], expected[i]) {
						t.Fatalf("row %d: typed roundtrip differs", i)
					}
				}
			case "query":
				if c.Input == nil || c.Rows != nil || c.ExpectedRows != nil || c.ExpectedStored != nil || c.EqualLengths {
					t.Fatal("invalid query case")
				}
				term, err := cipher.QueryTerm(ctx, plan, "value", "eq", conformanceValue(t, *c.Input))
				if c.ExpectedError != nil {
					if c.ExpectedValue != nil {
						t.Fatal("ambiguous query outcome")
					}
					runtimeRefusal(t, err, c)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if c.ExpectedValue == nil {
					t.Fatal("missing query outcome")
				}
				sealed, err := cipher.Seal(ctx, plan, []record.Source{{"value": conformanceValue(t, *c.ExpectedValue)}})
				if err != nil {
					t.Fatal(err)
				}
				if len(sealed) != 1 || len(term.Terms) != 1 || !bytes.Equal(term.Terms[0], sealed[0]["value"].Terms[record.Equality]) {
					t.Fatal("query differs from normalized stored value")
				}
			default:
				t.Fatalf("unknown operation %q", c.Operation)
			}
		})
	}
}
