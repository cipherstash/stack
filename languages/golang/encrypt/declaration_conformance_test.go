package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
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
		text := v.String()
		var value any
		var err error
		switch {
		case strings.ContainsAny(text, ".eE"):
			value, err = strconv.ParseFloat(text, 64)
		case strings.HasPrefix(text, "-"):
			value, err = strconv.ParseInt(text, 10, 64)
		default:
			value, err = strconv.ParseUint(text, 10, 64)
		}
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
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "declarations.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-declarations-v1" || corpus.Resolver != "none" || len(corpus.Cases) == 0 {
		t.Fatal("unsupported or empty declaration corpus")
	}
	wasm, err := os.ReadFile("testdata/stack_encrypt_guest_deterministic.wasm")
	if errors.Is(err, os.ErrNotExist) && os.Getenv("STACK_CONFORMANCE_REQUIRED") != "1" {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checker.Close() })
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
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
			if diagnostic.Code != expected.Code || !reflect.DeepEqual(diagnostic.Fields, expected.Fields) {
				t.Fatalf("got %s %#v; expected %s %#v", diagnostic.Code, diagnostic.Fields, expected.Code, expected.Fields)
			}
		})
	}
}
