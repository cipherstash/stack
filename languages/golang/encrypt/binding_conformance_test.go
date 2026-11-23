package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

type bindingCase struct {
	ID     string        `json:"id"`
	Label  string        `json:"label"`
	Scopes []contextPart `json:"scopes"`
	Bind   []contextPart `json:"bind"`
}
type bindingVector struct {
	Descriptor string `json:"descriptor"`
	Equality   string `json:"equality"`
	Ciphertext string `json:"ciphertext"`
	Contexts   string `json:"contexts"`
}

// A binding is in the stored context, after the scopes, and in no query
// context. Go seals and opens through Scope and Bind, and its term, its
// contexts text and the Rust ciphertext agree with the Rust vectors.
func TestBindingConformance(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	root := filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1")
	var corpus struct {
		Version              int           `json:"version"`
		Profile              string        `json:"profile"`
		RequiredCapabilities []string      `json:"required_capabilities"`
		Cases                []bindingCase `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join(root, "record-bindings-v1.cases.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-bindings-v1" || len(corpus.Cases) == 0 || !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"composition", "typed-extensions", "bindings", "frozen-open"}) {
		t.Fatal("unsupported bindings profile")
	}
	var expected struct {
		Version  int                      `json:"version"`
		Profile  string                   `json:"profile"`
		Producer string                   `json:"producer"`
		Cases    map[string]bindingVector `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join(root, "record-bindings-v1.expected.rust-native.json"), &expected)
	if expected.Version != 1 || expected.Profile != corpus.Profile || expected.Producer == "" || len(expected.Cases) != len(corpus.Cases) {
		t.Fatal("unsupported bindings vectors")
	}
	parts := func(t *testing.T, inputs []contextPart) []any {
		t.Helper()
		out := make([]any, 0, len(inputs))
		for _, part := range inputs {
			switch part.Type {
			case "bytes":
				b, err := hex.DecodeString(part.Text)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, b)
			case "string", "int32", "int64", "uint64":
				out = append(out, conformanceValue(t, conformanceInput(part)))
			default:
				t.Fatal("unsupported context part")
			}
		}
		return out
	}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatal("empty or repeated case ID")
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			want, ok := expected.Cases[c.ID]
			if !ok {
				t.Fatal("missing vector")
			}
			decode := func(s string) []byte {
				t.Helper()
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			label, e := record.ParseContext(c.Label)
			if e != nil {
				t.Fatal(e)
			}
			p := &record.Plan{Context: label, Fields: []record.Field{{Name: "text", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}}}}
			source := []record.Source{{"text": "hello"}}
			scoped := client.DefaultKeyset().Scope(parts(t, c.Scopes)...)
			bound := scoped.Bind(parts(t, c.Bind)...)

			// The cipher prints the contexts Rust pinned.
			shown, e := bound.Contexts(ctx, p)
			if e != nil {
				t.Fatal(e)
			}
			if shown != want.Contexts {
				t.Fatalf("contexts differ from Rust's:\n%s\nwant:\n%s", shown, want.Contexts)
			}

			// A fresh row's term is the pinned one: the binding is not in
			// the query context.
			fresh, e := bound.Seal(ctx, p, source)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(fresh[0]["text"].Terms[record.Equality], decode(want.Equality)) {
				t.Fatal("stored term differs")
			}
			// A query under the scopes alone derives it. A query through the
			// bound cipher is refused.
			query, e := scoped.QueryTerm(ctx, p, "text", "eq", "hello")
			if e != nil {
				t.Fatal(e)
			}
			if len(query.Terms) != 1 || !bytes.Equal(query.Terms[0], decode(want.Equality)) {
				t.Fatal("query differs")
			}
			if _, e := bound.QueryTerm(ctx, p, "text", "eq", "hello"); !errors.Is(e, encrypt.ErrEncoding) {
				t.Fatalf("a query with a binding: %v", e)
			}

			// The Rust ciphertext opens under the binding, and under no
			// other. A tampered binding and a binding left out both fail.
			frozen := []record.Sealed{{"text": {Ciphertext: decode(want.Ciphertext), Terms: map[record.Output][]byte{record.Equality: decode(want.Equality)}}}}
			for _, stored := range [][]record.Sealed{fresh, frozen} {
				opened, e := bound.Open(ctx, p, stored)
				if e != nil || !reflect.DeepEqual(opened, source) {
					t.Fatalf("open: %v; values differ: %v", e, !reflect.DeepEqual(opened, source))
				}
				tampered := make([]any, len(c.Bind))
				for i := range tampered {
					tampered[i] = "tampered"
				}
				if _, e := scoped.Bind(tampered...).Open(ctx, p, stored); e == nil {
					t.Fatal("a tampered binding opened the row")
				}
				if _, e := scoped.Open(ctx, p, stored); e == nil {
					t.Fatal("a binding left out opened the row")
				}
			}
		})
	}
}
