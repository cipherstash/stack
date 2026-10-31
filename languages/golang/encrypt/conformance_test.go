package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// This runner tests the record interface used by generated SDK code. Generated
// declarations have separate tests; this is not a substitute for SDK conformance.
const conformanceProfile = "record-scalars-v1"

type conformanceCorpus struct {
	Version              int               `json:"version"`
	Profile              string            `json:"profile"`
	Seed                 string            `json:"seed"`
	Context              []string          `json:"context"`
	Field                string            `json:"field"`
	RequiredCapabilities []string          `json:"required_capabilities"`
	Cases                []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Input struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"input"`
	ExpectedError *struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	} `json:"expected_error"`
}

type conformanceArtifact struct {
	Frame      string `json:"frame"`
	Ciphertext string `json:"ciphertext"`
	Equality   string `json:"equality"`
}

type conformanceArtifacts struct {
	Version  int                            `json:"version"`
	Profile  string                         `json:"profile"`
	Producer string                         `json:"producer"`
	Cases    map[string]conformanceArtifact `json:"cases"`
}

func readConformanceJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		t.Fatalf("%s: trailing JSON or invalid suffix: %v", path, err)
	}
}

func conformanceValue(t *testing.T, c conformanceCase) any {
	t.Helper()
	switch c.Input.Type {
	case "int32", "int64":
		bits := 64
		if c.Input.Type == "int32" {
			bits = 32
		}
		n, err := strconv.ParseInt(c.Input.Text, 10, bits)
		if err != nil {
			t.Fatal(err)
		}
		if bits == 32 {
			return int32(n)
		}
		return n
	case "uint64":
		n, err := strconv.ParseUint(c.Input.Text, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	case "bool":
		if c.Input.Text != "true" && c.Input.Text != "false" {
			t.Fatal("bool must be true or false")
		}
		return c.Input.Text == "true"
	case "string":
		return c.Input.Text
	case "null":
		if c.Input.Text != "" {
			t.Fatal("null has empty text")
		}
		return nil
	default:
		t.Fatalf("unsupported input type %q", c.Input.Type)
		return nil
	}
}

func TestStackConformance(t *testing.T) {
	root := filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1")
	var corpus conformanceCorpus
	readConformanceJSON(t, filepath.Join(root, "cases.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != conformanceProfile || len(corpus.Cases) == 0 {
		t.Fatal("unsupported or empty conformance corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "equality", "context-binding", "query-errors"}) {
		t.Fatal("unsupported required capabilities")
	}
	seen := make(map[string]bool)
	positive := make(map[string]bool)
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or duplicate case ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.ExpectedError == nil {
			positive[c.ID] = true
		}
	}
	var native conformanceArtifacts
	readConformanceJSON(t, filepath.Join(root, "native.json"), &native)
	if native.Version != 1 || native.Profile != conformanceProfile || native.Producer == "" || len(native.Cases) != len(positive) || len(positive) == 0 {
		t.Fatal("artifact profile or case set differs from the corpus")
	}
	for id := range native.Cases {
		if !positive[id] {
			t.Fatalf("unexpected artifact %q", id)
		}
	}
	seed, err := hex.DecodeString(corpus.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatal("expected 32-byte deterministic test seed")
	}
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte(seed))
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) && os.Getenv("STACK_CONFORMANCE_REQUIRED") != "1" {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cipher := client.DefaultKeyset()
	output := conformanceArtifacts{Version: 1, Profile: conformanceProfile, Producer: "go-wasi", Cases: make(map[string]conformanceArtifact)}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			plan := &record.Plan{Context: corpus.Context, Fields: []record.Field{{
				Name: corpus.Field, Kind: record.Kind(c.Kind), Outputs: []record.Output{record.Ciphertext, record.Equality},
			}}}
			input := conformanceValue(t, c)
			query, err := cipher.QueryTerm(ctx, plan, corpus.Field, "eq", input)
			if c.ExpectedError != nil {
				var diagnostic *encrypt.Diagnostic
				if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &diagnostic) {
					t.Fatalf("expected encoding diagnostic, got %v", err)
				}
				if diagnostic.Code != c.ExpectedError.Code || diagnostic.Reason() != c.ExpectedError.Reason || diagnostic.Field() != corpus.Field {
					t.Fatalf("unexpected diagnostic: %s reason=%s field=%s", diagnostic.Code, diagnostic.Reason(), diagnostic.Field())
				}
				return
			}
			if c.Kind != c.Input.Type {
				t.Fatal("positive case must use its declared type")
			}
			if err != nil {
				t.Fatal(err)
			}
			if query.Operator != "eq" || query.Index != record.Equality || query.Fidelity != record.Exact || query.Encoding != "bytes" || query.Domain != "" || len(query.Terms) != 1 {
				t.Fatal("unexpected equality operand metadata")
			}
			want := native.Cases[c.ID]
			encoded, err := vcffi.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(encoded) != want.Frame || hex.EncodeToString(query.Terms[0]) != want.Equality {
				t.Fatal("typed frame or equality bytes disagree with the native vector")
			}
			decode := func(text string) []byte {
				t.Helper()
				b, err := hex.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			source := []record.Source{{corpus.Field: input}}
			fresh, err := cipher.Seal(ctx, plan, source)
			if err != nil {
				t.Fatal(err)
			}
			if len(fresh) != 1 || !bytes.Equal(fresh[0][corpus.Field].Terms[record.Equality], query.Terms[0]) {
				t.Fatal("stored equality differs from query equality")
			}
			frozen := []record.Sealed{{corpus.Field: {Ciphertext: decode(want.Ciphertext), Terms: map[record.Output][]byte{record.Equality: decode(want.Equality)}}}}
			for name, rows := range map[string][]record.Sealed{"native": frozen, "go": fresh} {
				opened, err := cipher.Open(ctx, plan, rows)
				if err != nil || !reflect.DeepEqual(opened, source) {
					t.Fatalf("%s cross-open: err=%v; typed value mismatch=%v", name, err, !reflect.DeepEqual(opened, source))
				}
			}
			wrong := *plan
			wrong.Context = append(append([]string{}, corpus.Context...), "wrong")
			if _, err := cipher.Open(ctx, &wrong, frozen); !errors.Is(err, encrypt.ErrForbidden) {
				t.Fatalf("wrong context: expected forbidden key retrieval, got %v", err)
			}
			output.Cases[c.ID] = conformanceArtifact{Frame: want.Frame, Ciphertext: hex.EncodeToString(fresh[0][corpus.Field].Ciphertext), Equality: hex.EncodeToString(query.Terms[0])}
		})
	}
	if t.Failed() {
		return
	}
	if path := os.Getenv("STACK_CONFORMANCE_OUTPUT"); path != "" {
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
