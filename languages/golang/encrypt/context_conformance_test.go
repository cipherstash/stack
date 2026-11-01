package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

type contextCase struct {
	ID    string        `json:"id"`
	Base  string        `json:"base"`
	Label string        `json:"label"`
	Parts []contextPart `json:"parts"`
}
type contextVector struct {
	ContextFrame string `json:"context_frame"`
	Descriptor   string `json:"descriptor"`
	AAD          string `json:"aad"`
	PRF          string `json:"prf"`
	Ciphertext   string `json:"ciphertext"`
	Equality     string `json:"equality"`
}

func TestContextConformance(t *testing.T) {
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
		Cases                []contextCase `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join(root, "contexts.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-contexts-v1" || len(corpus.Cases) == 0 || !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"composition", "typed-extensions", "context-fields", "frozen-open"}) {
		t.Fatal("unsupported context profile")
	}
	var vectors map[string]contextVector
	readConformanceJSON(t, filepath.Join(root, "contexts-native.json"), &vectors)
	if len(vectors) != len(corpus.Cases) {
		t.Fatal("vector case set differs")
	}
	t.Run("grouped-extension-is-not-a-go-record-part", func(t *testing.T) {
		cipher := client.DefaultKeyset().Extend([]any{uint64(7), "eu"})
		_, err := testusers.NoteFields.Text.Eq(ctx, cipher.Context("tenants/acme"), "hello")
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("grouped extension: %v", err)
		}
	})
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatal("empty or repeated case ID")
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			want, ok := vectors[c.ID]
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
			switch c.Base {
			case "literal":
			case "field":
				p.Context = nil
				p.ContextField = "tenant"
				source[0]["tenant"] = c.Label
			default:
				t.Fatal("unknown context base")
			}
			cipher := client.DefaultKeyset()
			parts := make([]any, 0, len(c.Parts))
			for _, part := range c.Parts {
				var v any
				switch part.Type {
				case "bytes":
					v = decode(part.Text)
				case "string", "int32", "int64", "uint64":
					v = conformanceValue(t, conformanceInput(part))
				default:
					t.Fatal("unsupported context part")
				}
				parts = append(parts, v)
				cipher = cipher.Extend(v)
			}
			// Compare the precise context tree that native Rust encoded to AAD/PRF.
			// Go has no independent public AAD or descriptor encoder.
			resolved := *p
			resolved.Context = label
			resolved.ContextField = ""
			resolved.Extension = parts
			framed, e := vcffi.Marshal(resolved.FieldContext(p.Fields[0]))
			if e != nil {
				t.Fatal(e)
			}
			if hex.EncodeToString(framed) != want.ContextFrame {
				t.Fatal("context tree differs from native")
			}
			if want.Descriptor == "" || len(decode(want.AAD)) == 0 || len(decode(want.PRF)) == 0 {
				t.Fatal("missing canonical context observations")
			}
			fresh, e := cipher.Seal(ctx, p, source)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(fresh[0]["text"].Terms[record.Equality], decode(want.Equality)) {
				t.Fatal("stored term differs")
			}
			frozen := []record.Sealed{{"text": {Ciphertext: decode(want.Ciphertext), Terms: map[record.Output][]byte{record.Equality: decode(want.Equality)}}}}
			if c.Base == "field" {
				frozen[0]["tenant"] = record.Outputs{Context: c.Label}
			}
			for _, stored := range [][]record.Sealed{fresh, frozen} {
				opened, e := cipher.Open(ctx, p, stored)
				if e != nil || !reflect.DeepEqual(opened, source) {
					t.Fatalf("open: %v; values differ: %v", e, !reflect.DeepEqual(opened, source))
				}
			}
			queryCipher := cipher
			if c.Base == "field" {
				queryCipher = cipher.Context(c.Label)
			}
			query, e := queryCipher.QueryTerm(ctx, p, "text", "eq", "hello")
			if e != nil {
				t.Fatal(e)
			}
			if len(query.Terms) != 1 || !bytes.Equal(query.Terms[0], decode(want.Equality)) {
				t.Fatal("query differs")
			}
			// Variadic and repeated calls must agree, including a no-op Extend().
			combined := client.DefaultKeyset().Extend(parts...).Extend()
			if c.Base == "field" {
				combined = combined.Context(c.Label)
			}
			q, e := combined.QueryTerm(ctx, p, "text", "eq", "hello")
			if e != nil || !reflect.DeepEqual(q.Terms, query.Terms) {
				t.Fatalf("combined extensions: %v", e)
			}
			if c.Base == "field" {
				notes := []testusers.Note{{Tenant: c.Label, Text: "hello", ID: 0}}
				sealed, e := testusers.EncryptNote(ctx, cipher, notes)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(sealed[0].Text.Equality, decode(want.Equality)) {
					t.Fatal("generated write differs")
				}
				sealed[0].Text.Ciphertext = decode(want.Ciphertext)
				opened, e := testusers.DecryptNote(ctx, cipher, sealed)
				if e != nil || !reflect.DeepEqual(opened, notes) {
					t.Fatalf("generated cross-open: %v", e)
				}
				q, e := testusers.NoteFields.Text.Eq(ctx, queryCipher, "hello")
				if e != nil || !q.Equal(decode(want.Equality)) {
					t.Fatalf("generated query: %v", e)
				}
			}
		})
	}
}

type contextBoundary struct {
	ID         string   `json:"id"`
	Tenants    []string `json:"tenants"`
	Expected   string   `json:"expected"`
	Mutation   string   `json:"mutation"`
	Outcome    string   `json:"outcome"`
	Retrievals int      `json:"retrievals"`
}

func TestContextBoundaries(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wasm, err := encrypt.DeterministicGuest()
	if err != nil {
		t.Fatal(err)
	}
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checker.Close() })
	var corpus struct {
		Version int               `json:"version"`
		Profile string            `json:"profile"`
		Cases   []contextBoundary `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "context-boundaries.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "context-boundaries-v1" || len(corpus.Cases) == 0 {
		t.Fatal("unsupported boundary profile")
	}
	p := &record.Plan{ContextField: "tenant", Fields: []record.Field{{Name: "text", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}}}}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatal("empty or repeated ID")
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			rows := make([]record.Source, len(c.Tenants))
			for i, tenant := range c.Tenants {
				rows[i] = record.Source{"tenant": tenant, "text": "hello"}
			}
			cipher := client.DefaultKeyset()
			sealed, e := cipher.Seal(ctx, p, rows)
			if e != nil {
				t.Fatal(e)
			}
			tree := make([]any, len(sealed))
			for i, row := range sealed {
				tree[i] = map[string]any{"tenant": map[string]any{"passthrough": vcvalue.Plain{V: row["tenant"].Context}}, "text": map[string]any{"c": encrypt.Ciphertext(row["text"].Ciphertext), "eq": vcvalue.Plain{V: row["text"].Terms[record.Equality]}}}
			}
			switch c.Mutation {
			case "none":
			case "tamper", "empty", "missing":
				if len(tree) == 0 {
					t.Fatal("mutation requires a row")
				}
				row := tree[len(tree)-1].(map[string]any)
				if c.Mutation == "missing" {
					delete(row, "tenant")
				} else {
					tenant := ""
					if c.Mutation == "tamper" {
						tenant = "tenants/globex"
					}
					row["tenant"] = map[string]any{"passthrough": vcvalue.Plain{V: tenant}}
				}
			default:
				t.Fatal("unknown mutation")
			}
			_, preflight := checker.OpenTreeForTest(ctx, tree, p, c.Expected)
			// An uninitialised guest cannot retrieve keys: valid shapes reach ErrState.
			switch c.Outcome {
			case "success", "authentication":
				if !errors.Is(preflight, encrypt.ErrState) {
					t.Fatalf("preflight: %v", preflight)
				}
			case "mismatch", "shape":
				if preflight == nil || errors.Is(preflight, encrypt.ErrState) {
					t.Fatalf("expected key-free refusal: %v", preflight)
				}
			default:
				t.Fatal("unknown outcome")
			}
			reader := cipher
			if c.Expected != "" {
				reader = reader.Context(c.Expected)
			}
			opened, e := reader.OpenTreeForTest(ctx, tree, p)
			switch c.Outcome {
			case "success":
				if e != nil || !reflect.DeepEqual(opened, rows) {
					t.Fatalf("open: %v; rows differ: %v", e, !reflect.DeepEqual(opened, rows))
				}
				want := 1
				if len(rows) == 0 {
					want = 0
				}
				if c.Retrievals != want {
					t.Fatal("invalid retrieval expectation")
				}
			case "mismatch":
				if !errors.Is(e, encrypt.ErrContextMismatch) || c.Retrievals != 0 {
					t.Fatalf("mismatch: %v", e)
				}
			case "shape":
				if !errors.Is(e, encrypt.ErrEncoding) || c.Retrievals != 0 {
					t.Fatalf("shape: %v", e)
				}
			case "authentication":
				if !errors.Is(e, encrypt.ErrForbidden) || c.Retrievals != 1 {
					t.Fatalf("tampering: %v", e)
				}
			}
		})
	}
}

// Go's zero values must not make a missing or null field valid when Rust's
// required Deserialize fields reject it. The corpus is a strict shared format.
func decodeRequiredContextJSON(data []byte, out any, required ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing or null %s", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

type contextPart conformanceInput

func (p *contextPart) UnmarshalJSON(data []byte) error {
	type plain contextPart
	return decodeRequiredContextJSON(data, (*plain)(p), "type", "text")
}
func (c *contextCase) UnmarshalJSON(data []byte) error {
	type plain contextCase
	return decodeRequiredContextJSON(data, (*plain)(c), "id", "base", "label", "parts")
}
func (v *contextVector) UnmarshalJSON(data []byte) error {
	type plain contextVector
	return decodeRequiredContextJSON(data, (*plain)(v), "context_frame", "descriptor", "aad", "prf", "ciphertext", "equality")
}
func (c *contextBoundary) UnmarshalJSON(data []byte) error {
	type plain contextBoundary
	return decodeRequiredContextJSON(data, (*plain)(c), "id", "tenants", "expected", "mutation", "outcome", "retrievals")
}
