package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

type declarationCase struct {
	ID    string `json:"id"`
	Input struct {
		JSON     json.RawMessage `json:"json"`
		FrameHex *string         `json:"frame_hex"`
	} `json:"input"`
	Accepted      *bool             `json:"accepted"`
	ExpectedError *declarationError `json:"expected_error"`
	BoundaryError *declarationError `json:"boundary_error"`
	// Only native Rust exposes the parsed plan. Go checks acceptance and the
	// ABI diagnostic; it makes no claim to observe normalization independently.
	Normalized json.RawMessage `json:"normalized"`
}

type declarationError struct {
	Code   string         `json:"code"`
	Fields map[string]any `json:"fields"`
}

// The corpus JSON projection fixes object order lexically, positive integers
// as uint64 and negative integers as int64. This is test input conversion,
// not SDK normalization. Non-JSON transport shapes use frame_hex instead.
func declarationValue(t *testing.T, value any) any {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		object := make(vcvalue.Object, 0, len(keys))
		for _, key := range keys {
			object = append(object, vcvalue.Field{Key: key, Value: declarationValue(t, v[key])})
		}
		return object
	case []any:
		for i := range v {
			v[i] = declarationValue(t, v[i])
		}
		return v
	case json.Number:
		value, err := declarationNumber(v.String())
		if err != nil {
			t.Fatal(err)
		}
		return value
	default:
		return v
	}
}

func TestDeclarationConformance(t *testing.T) {
	var corpus struct {
		Version  int               `json:"version"`
		Profile  string            `json:"profile"`
		Resolver string            `json:"resolver"`
		Cases    []declarationCase `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "record-declarations-v1.cases.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-declarations-v1" || corpus.Resolver != "none" || len(corpus.Cases) == 0 {
		t.Fatal("unsupported or empty declaration corpus")
	}
	var hostPlans map[string]record.Plan
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "record-declarations-v1.inputs.go.json"), &hostPlans)
	for name, load := range map[string]func() ([]byte, error){"release": encrypt.PlainGuest, "deterministic": encrypt.DeterministicGuest} {
		t.Run(name, func(t *testing.T) {
			wasm, err := load()
			skipMissingConformanceGuest(t, err)
			if err != nil {
				t.Fatal(err)
			}
			checker, err := encrypt.NewCheckerOver(context.Background(), wasm)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = checker.Close() })
			checkDeclarationCases(t, checker, corpus.Cases, hostPlans)
		})
	}
}

func checkDeclarationCases(t *testing.T, checker *encrypt.Checker, cases []declarationCase, hostPlans map[string]record.Plan) {
	t.Helper()
	ctx := context.Background()
	for id := range hostPlans {
		found := false
		for _, c := range cases {
			if c.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("host plan has no shared case: %s", id)
		}
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or duplicate case ID %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			if c.Accepted == nil {
				t.Fatal("missing accepted outcome")
			}
			accepted := *c.Accepted
			if accepted != (c.ExpectedError == nil) || (!accepted && len(c.Normalized) != 0) {
				t.Fatal("contradictory expected outcome")
			}
			if (len(c.Input.JSON) == 0) == (c.Input.FrameHex == nil) {
				t.Fatal("expected exactly one input representation")
			}
			var frame []byte
			var err error
			if c.Input.FrameHex != nil {
				frame, err = hex.DecodeString(*c.Input.FrameHex)
			} else {
				decoder := json.NewDecoder(bytes.NewReader(c.Input.JSON))
				decoder.UseNumber()
				var value any
				if err := decoder.Decode(&value); err != nil {
					t.Fatal(err)
				}
				frame, err = vcffi.Marshal(declarationValue(t, value))
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan, ok := hostPlans[c.ID]; ok {
				hostErr := checker.Check(ctx, &plan)
				if (hostErr == nil) != accepted {
					t.Fatalf("host Check: %v; accepted=%v", hostErr, accepted)
				}
				if hostErr != nil && !errors.Is(hostErr, encrypt.ErrEncoding) {
					t.Fatalf("host Check: expected ErrEncoding, got %v", hostErr)
				}
			}
			err = checker.CheckFrameForTest(ctx, frame)
			expected := c.ExpectedError
			if c.BoundaryError != nil {
				if accepted || c.Input.FrameHex == nil {
					t.Fatal("boundary refusal requires a rejected raw frame")
				}
				if _, decodeErr := vcffi.Unmarshal(frame); decodeErr == nil {
					t.Fatal("boundary refusal requires a malformed frame")
				}
				expected = c.BoundaryError
			}
			if accepted {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var diagnostic *encrypt.Diagnostic
			if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &diagnostic) {
				t.Fatalf("expected encoding diagnostic, got %v", err)
			}
			if diagnostic.Code != expected.Code || !sameDiagnosticFields(t, diagnostic.Fields, expected.Fields) {
				t.Fatalf("got %s %#v; expected %s %#v", diagnostic.Code, diagnostic.Fields, expected.Code, expected.Fields)
			}
		})
	}
}

// Compare JSON payload values without float64 rounding or int64/uint64 type
// accidents. UseNumber in readConformanceJSON preserves expected integers.
func sameDiagnosticFields(t *testing.T, actual, expected map[string]any) bool {
	t.Helper()
	a, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(a, b)
}

func TestDiagnosticNumericFields(t *testing.T) {
	if !sameDiagnosticFields(t, map[string]any{"n": uint64(18446744073709551615), "m": int64(-1)}, map[string]any{"n": json.Number("18446744073709551615"), "m": json.Number("-1")}) {
		t.Fatal("integer payload changed")
	}
	if sameDiagnosticFields(t, map[string]any{"n": uint64(18446744073709551615)}, map[string]any{"n": json.Number("18446744073709551614")}) {
		t.Fatal("integer precision lost")
	}
}

func declarationNumber(text string) (any, error) {
	switch {
	case strings.ContainsAny(text, ".eE"):
		return strconv.ParseFloat(text, 64)
	case strings.HasPrefix(text, "-"):
		return strconv.ParseInt(text, 10, 64)
	default:
		return strconv.ParseUint(text, 10, 64)
	}
}
func TestDeclarationNumberProjection(t *testing.T) {
	zero, err := declarationNumber("-0")
	if err != nil || zero != int64(0) {
		t.Fatalf("-0: %v %v", zero, err)
	}
	for _, invalid := range []string{"18446744073709551616", "-9223372036854775809", "1e400"} {
		if _, err := declarationNumber(invalid); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
}
