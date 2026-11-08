package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

type valueCase struct {
	ID            string            `json:"id"`
	Kind          string            `json:"kind"`
	Null          string            `json:"null"`
	Outputs       []string          `json:"outputs"`
	Input         conformanceInput  `json:"input"`
	Frame         *string           `json:"frame"`
	Companion     *conformanceInput `json:"companion"`
	EqualQuery    *conformanceInput `json:"equal_query"`
	Unanswered    []string          `json:"unanswered"`
	ExpectedError *struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
		Field  string `json:"field"`
	} `json:"expected_error"`
}

type hostConversionCase struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
}

// hostConstruction is a Go value the host refuses to convert before the
// engine sees it. The names are the corpus's closed vocabulary; the Rust
// runner checks the same list.
func hostConstruction(t *testing.T, name string) any {
	t.Helper()
	switch name {
	case "zero_date":
		return encrypt.Date{}
	case "decimal_scale_29":
		return encrypt.Decimal{Scale: 29}
	case "timestamp_year_300000":
		return time.Date(300000, 1, 1, 0, 0, 0, 0, time.UTC)
	case "complex128":
		return complex(1, 2)
	case "map_int_key":
		return map[int]string{1: "a"}
	case "channel":
		return make(chan int)
	}
	t.Fatalf("unknown host construction %q", name)
	return nil
}

// sameValue compares an opened value with the one sealed: a time.Time by
// its instant (the opened one is in UTC, the input carries the location it
// was parsed with), bytes by content (an empty slice may come back nil), a
// float by its bits (so -0 is not 0), anything else structurally.
func sameValue(got, want any) bool {
	switch w := want.(type) {
	case time.Time:
		g, ok := got.(time.Time)
		return ok && g.Equal(w) && g.Location() == time.UTC
	case []byte:
		g, ok := got.([]byte)
		return ok && bytes.Equal(g, w)
	case float32:
		g, ok := got.(float32)
		return ok && math.Float32bits(g) == math.Float32bits(w)
	case float64:
		g, ok := got.(float64)
		return ok && math.Float64bits(g) == math.Float64bits(w)
	}
	return reflect.DeepEqual(got, want)
}

func TestValueConformance(t *testing.T) {
	var corpus struct {
		Version              int                  `json:"version"`
		Profile              string               `json:"profile"`
		RequiredCapabilities []string             `json:"required_capabilities"`
		Cases                []valueCase          `json:"cases"`
		HostConversions      []hostConversionCase `json:"host_conversions"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "record-values-v1.cases.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-values-v1" || len(corpus.Cases) == 0 || len(corpus.HostConversions) == 0 {
		t.Fatal("unsupported or empty value corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "equality", "value-kinds", "null-policies"}) {
		t.Fatal("unsupported capabilities")
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
			if c.Null != "" && c.Null != "sql" && c.Null != "sealed" {
				t.Fatalf("unknown null policy %q", c.Null)
			}
			if !record.Kind(c.Kind).Known() || c.Kind == "" || len(c.Outputs) == 0 || c.Outputs[0] != "c" {
				t.Fatal("unsupported declaration")
			}
			isNull := c.Input.Type == "null"
			if (c.Frame == nil) != isNull {
				t.Fatal("a frame is frozen for every value, and for no null")
			}
			outputs := make([]record.Output, len(c.Outputs))
			for i, o := range c.Outputs {
				outputs[i] = record.Output(o)
			}
			plan := &record.Plan{Context: []string{"conformance"}, Fields: []record.Field{{Name: "value", Kind: record.Kind(c.Kind), Null: record.Null(c.Null), Outputs: outputs}}}
			input := conformanceValue(t, c.Input)
			if c.Frame != nil {
				encoded, err := vcffi.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(encoded) != *c.Frame {
					t.Fatalf("typed frame %x differs from the frozen %s", encoded, *c.Frame)
				}
			}
			rows := []record.Source{{"value": input}}
			if c.Companion != nil {
				rows = append(rows, record.Source{"value": conformanceValue(t, *c.Companion)})
			}
			sealed, err := cipher.Seal(ctx, plan, rows)
			if c.ExpectedError != nil {
				if c.Companion != nil || c.EqualQuery != nil {
					t.Fatal("a refused case has no companion or query")
				}
				assertConformanceDiagnostic(t, err, c.ExpectedError.Code, c.ExpectedError.Reason, c.ExpectedError.Field)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(sealed) != len(rows) {
				t.Fatal("row count differs")
			}
			stored, present := sealed[0]["value"]
			if present == (isNull && c.Null == "sql") {
				t.Fatalf("stored=%v for a %q null", present, c.Null)
			}
			// Every stored term is the term a query of the value derives,
			// save an index no operator answers, whose query is refused.
			check := func(t *testing.T, row record.Outputs, value any, equal *conformanceInput) {
				t.Helper()
				if len(row.Ciphertext) == 0 || len(row.Terms) != len(c.Outputs)-1 {
					t.Fatalf("stored %d terms for %v", len(row.Terms), c.Outputs[1:])
				}
				for _, o := range c.Outputs[1:] {
					operator := "eq"
					if o == "ore" || o == "ope" {
						operator = "lt"
					}
					term, err := cipher.QueryTerm(ctx, plan, "value", operator, value)
					unanswered := false
					for _, u := range c.Unanswered {
						unanswered = unanswered || u == o
					}
					if unanswered {
						assertConformanceDiagnostic(t, err, "stack_encrypt::dynamic_source", "operator_not_answered", "value")
						continue
					}
					if err != nil || len(term.Terms) != 1 || !bytes.Equal(term.Terms[0], row.Terms[record.Output(o)]) {
						t.Fatalf("%s: stored/query term mismatch: %v", o, err)
					}
					if o == "eq" && equal != nil {
						other, err := cipher.QueryTerm(ctx, plan, "value", "eq", conformanceValue(t, *equal))
						if err != nil || len(other.Terms) != 1 || !bytes.Equal(other.Terms[0], row.Terms[record.Equality]) {
							t.Fatalf("the equal spelling derives another term: %v", err)
						}
					}
				}
			}
			if present {
				check(t, stored, input, c.EqualQuery)
			}
			if c.Companion != nil {
				companion := sealed[1]["value"]
				check(t, companion, rows[1]["value"], nil)
				if present && len(companion.Ciphertext) != len(stored.Ciphertext) {
					t.Fatal("a sealed null is as long as a value")
				}
			}
			opened, err := cipher.Open(ctx, plan, sealed)
			if err != nil {
				t.Fatal(err)
			}
			if len(opened) != len(rows) {
				t.Fatal("opened row count differs")
			}
			for i, row := range rows {
				if len(opened[i]) != 1 || !sameValue(opened[i]["value"], row["value"]) {
					t.Fatalf("row %d: opened %#v, sealed %#v", i, opened[i]["value"], row["value"])
				}
			}
		})
	}
	for _, c := range corpus.HostConversions {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or repeated ID %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			if c.Language != "go" {
				t.Skipf("a %s host conversion", c.Language)
			}
			plan := &record.Plan{Context: []string{"conformance"}, Fields: []record.Field{{Name: "value", Kind: record.Kind(c.Kind), Outputs: []record.Output{record.Ciphertext}}}}
			value := hostConstruction(t, c.Value)
			// The host refuses the conversion itself: ErrEncoding with no
			// engine diagnostic, because the guest was never asked.
			var diagnostic *encrypt.Diagnostic
			if _, err := cipher.Seal(ctx, plan, []record.Source{{"value": value}}); !errors.Is(err, encrypt.ErrEncoding) || errors.As(err, &diagnostic) {
				t.Fatalf("Seal: expected a host refusal, got %v", err)
			}
			if _, err := cipher.QueryTerm(ctx, plan, "value", "eq", value); !errors.Is(err, encrypt.ErrEncoding) || errors.As(err, &diagnostic) {
				t.Fatalf("QueryTerm: expected a host refusal, got %v", err)
			}
		})
	}
}
