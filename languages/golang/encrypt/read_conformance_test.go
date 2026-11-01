package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	ContextFieldName string            `json:"context_field_name"`
	ExpectedContext  *string           `json:"expected_context"`
	Adapter          bool              `json:"adapter"`
	CheckError       *declarationError `json:"check_error"`
	Expected         struct {
		Stage      string                         `json:"stage"`
		Retrievals int                            `json:"retrievals"`
		Error      *declarationError              `json:"error"`
		Rows       *[]map[string]conformanceInput `json:"rows"`
	} `json:"expected"`
}

func readPlan(d readDeclaration, contextField bool, contextName string) *record.Plan {
	p := &record.Plan{Context: []string{"conformance"}, Fields: []record.Field{{Name: "value", Kind: record.Kind(d.Kind), Null: record.Null(d.Null), Outputs: []record.Output{record.Ciphertext, record.Equality}}}}
	if contextField {
		p.Context = nil
		p.ContextField = contextName
	}
	return p
}

func readTree(stored []record.Sealed, contextField bool, contextName string) []any {
	batch := make([]any, len(stored))
	for i, row := range stored {
		fields := map[string]any{}
		if contextField {
			fields[contextName] = map[string]any{"passthrough": vcvalue.Plain{V: row[contextName].Context}}
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
	switch c.Mutation.Kind {
	case "none", "row_plain", "drop_value", "field_plain", "extra_field", "drop_tenant", "tenant_no_payload", "tenant_number", "drop_c", "drop_eq", "c_plain", "extra_output":
	default:
		t.Fatalf("unknown mutation %q", c.Mutation.Kind)
	}
	contextName := c.ContextFieldName
	if contextName == "" {
		contextName = "tenant"
	}
	i := c.Mutation.Row
	if i < 0 || i >= len(batch) {
		t.Fatal("mutation row out of range")
	}
	plain := vcvalue.Plain{V: int32(34)}
	if c.Mutation.Kind == "row_plain" {
		batch[i] = plain
		return
	}
	fields := readMap(t, batch[i], "row")
	switch c.Mutation.Kind {
	case "none":
	case "drop_value":
		delete(fields, "value")
	case "field_plain":
		fields["value"] = plain
	case "extra_field":
		fields["extra"] = plain
	case "drop_tenant":
		delete(fields, contextName)
	case "tenant_no_payload":
		fields[contextName] = map[string]any{}
	case "tenant_number":
		readMap(t, fields[contextName], "context outputs")["passthrough"] = plain
	default:
		outputs := readMap(t, fields["value"], "value outputs")
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
	if diagnostic.Code != want.Code || !sameDiagnosticFields(t, diagnostic.Fields, want.Fields) {
		t.Fatalf("got %s %#v; want %s %#v", diagnostic.Code, diagnostic.Fields, want.Code, want.Fields)
	}
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
	wasm, err := encrypt.DeterministicGuest()
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
			if err := validateReadCase(c); err != nil {
				t.Fatal(err)
			}
			name := c.ContextFieldName
			if name == "" {
				name = "tenant"
			}
			expectedContext := ""
			if c.ExpectedContext != nil {
				expectedContext = *c.ExpectedContext
			}
			write, read := readPlan(c.Write, c.ContextField, name), readPlan(c.Read, c.ContextField, name)
			stored, err := cipher.Seal(ctx, write, runtimeRows(t, c.Rows))
			if err != nil {
				t.Fatal(err)
			}
			tree := readTree(stored, c.ContextField, name)
			mutateRead(t, tree, c)
			// Without a cipher, preflight must reject malformed shapes/contexts.
			// Valid shapes (including concealed type mismatches) must reach ErrState.
			_, err = checker.OpenTreeForTest(ctx, tree, read, expectedContext)
			if c.CheckError != nil {
				readRefusal(t, err, c.CheckError)
			} else if !errors.Is(err, encrypt.ErrState) {
				t.Fatalf("expected state boundary after preflight, got %v", err)
			}
			reader := cipher
			if c.ExpectedContext != nil {
				reader = cipher.Context(expectedContext)
			}
			out, err := reader.OpenTreeForTest(ctx, tree, read)
			// The raw checker above observes the guest; a configured Cipher
			// refuses this combination on the host before reaching it.
			if c.ExpectedContext != nil && !c.ContextField {
				if !errors.Is(err, encrypt.ErrEncoding) {
					t.Fatalf("expected host context refusal, got %v", err)
				}
				if !c.Adapter {
					t.Fatal("host context refusal must exercise Open too")
				}
				if _, err := reader.Open(ctx, read, stored); !errors.Is(err, encrypt.ErrEncoding) {
					t.Fatalf("Open: expected host context refusal, got %v", err)
				}
				return
			}
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
				if !reflect.DeepEqual(out, runtimeRows(t, *c.Expected.Rows)) {
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
				if c.ExpectedContext != nil {
					reader = cipher.Context(expectedContext)
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

func readMap(t *testing.T, value any, name string) map[string]any {
	t.Helper()
	fields, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected map, got %T", name, value)
	}
	return fields
}

// Standard JSON decoding rejects unknown fields, but not missing required
// fields. Keep the same required/null rules as Rust's Deserialize structs.
func (c *readCase) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	require := func(fields map[string]json.RawMessage, names ...string) error {
		for _, name := range names {
			if len(fields[name]) == 0 || bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
				return fmt.Errorf("missing or null %s", name)
			}
		}
		return nil
	}
	if err := require(fields, "id", "write", "read", "context_field", "rows", "mutation", "adapter", "expected"); err != nil {
		return err
	}
	for key, names := range map[string][]string{"write": {"kind", "null"}, "read": {"kind", "null"}, "mutation": {"kind", "row"}, "expected": {"stage", "retrievals"}} {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(fields[key], &nested); err != nil {
			return err
		}
		if err := require(nested, names...); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	type plain readCase
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode((*plain)(c))
}

func validateReadCase(c readCase) error {
	if c.ExpectedContext != nil {
		if _, err := record.ParseContext(*c.ExpectedContext); err != nil {
			return fmt.Errorf("expected_context: %w", err)
		}
	}
	if c.ContextFieldName != "" {
		if !c.ContextField {
			return errors.New("context_field_name without context field")
		}
		if err := record.CheckSegment(c.ContextFieldName); err != nil {
			return err
		}
	}
	for _, d := range []readDeclaration{c.Write, c.Read} {
		if d.Null != "" && d.Null != "sql" && d.Null != "sealed" {
			return errors.New("unknown null policy")
		}
		if !record.Kind(d.Kind).Known() || d.Kind == "" {
			return errors.New("unknown kind")
		}
	}
	switch c.Expected.Stage {
	case "success":
		if c.CheckError != nil || c.Expected.Error != nil || c.Expected.Rows == nil || c.Expected.Retrievals < 0 || c.Expected.Retrievals > 1 {
			return errors.New("inconsistent success")
		}
	case "authenticated":
		if c.CheckError != nil || c.Expected.Retrievals != 1 {
			return errors.New("inconsistent authenticated stage")
		}
	case "shape", "preflight":
		if c.Expected.Retrievals != 0 || c.CheckError == nil {
			return errors.New("inconsistent preflight stage")
		}
	default:
		return errors.New("unknown stage")
	}
	if c.Expected.Stage != "success" && (c.Expected.Error == nil || c.Expected.Rows != nil) {
		return errors.New("inconsistent refusal")
	}
	return nil
}

func TestReadCorpusSchema(t *testing.T) {
	const valid = `{"id":"schema","write":{"kind":"int32","null":""},"read":{"kind":"int32","null":""},"context_field":false,"rows":[],"mutation":{"kind":"none","row":0},"adapter":false,"expected":{"stage":"success","retrievals":0,"rows":[]}}`
	check := func(data []byte) error {
		var c readCase
		if err := json.Unmarshal(data, &c); err != nil {
			return err
		}
		return validateReadCase(c)
	}
	if err := check([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, path := range [][]string{{"context_field"}, {"adapter"}, {"mutation", "row"}, {"expected", "retrievals"}, {"write", "kind"}} {
		t.Run("missing-"+path[len(path)-1], func(t *testing.T) {
			var data map[string]any
			if err := json.Unmarshal([]byte(valid), &data); err != nil {
				t.Fatal(err)
			}
			if len(path) == 1 {
				delete(data, path[0])
			} else {
				delete(data[path[0]].(map[string]any), path[1])
			}
			encoded, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			if err := check(encoded); err == nil {
				t.Fatal("accepted missing required field")
			}
		})
	}
	for name, mutate := range map[string]func(*readCase){
		"empty-context": func(c *readCase) { empty := ""; c.ExpectedContext = &empty },
		"authenticated-preflight-error": func(c *readCase) {
			c.Expected.Stage = "authenticated"
			c.Expected.Retrievals = 1
			c.CheckError = &declarationError{}
			c.Expected.Error = &declarationError{}
			c.Expected.Rows = nil
		},
		"preflight-retrieval": func(c *readCase) {
			c.Expected.Stage = "preflight"
			c.Expected.Retrievals = 1
			c.CheckError = &declarationError{}
			c.Expected.Error = &declarationError{}
			c.Expected.Rows = nil
		},
		"success-check-error": func(c *readCase) { c.CheckError = &declarationError{} },
	} {
		t.Run(name, func(t *testing.T) {
			var c readCase
			if err := json.Unmarshal([]byte(valid), &c); err != nil {
				t.Fatal(err)
			}
			mutate(&c)
			if err := validateReadCase(c); err == nil {
				t.Fatal("accepted inconsistent expectation")
			}
		})
	}
}

func TestReadTreePreservesCipherScope(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) && os.Getenv("STACK_CONFORMANCE_REQUIRED") != "1" {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cipher := client.DefaultKeyset().Extend("region", int32(7)).Context("tenants/acme")
	plan := readPlan(readDeclaration{Kind: "int32"}, true, "tenant")
	rows := []record.Source{{"tenant": "tenants/acme", "value": int32(34)}}
	stored, err := cipher.Seal(ctx, plan, rows)
	if err != nil {
		t.Fatal(err)
	}
	tree := readTree(stored, true, "tenant")
	opened, err := cipher.OpenTreeForTest(ctx, tree, plan)
	if err != nil || !reflect.DeepEqual(opened, rows) {
		t.Fatalf("extended context roundtrip: %v", err)
	}
	if _, err := cipher.Context("tenants/other").OpenTreeForTest(ctx, tree, plan); !errors.Is(err, encrypt.ErrContextMismatch) {
		t.Fatalf("context mismatch: %v", err)
	}
	if _, err := cipher.Context("invalid/(label)").OpenTreeForTest(ctx, tree, plan); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("invalid cipher: %v", err)
	}
	if _, err := cipher.OpenTreeForTest(ctx, tree, nil); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("invalid plan: %v", err)
	}
	if _, err := cipher.OpenTreeForTest(ctx, []any{struct{}{}}, plan); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("marshal error lost ErrEncoding: %v", err)
	}
}
