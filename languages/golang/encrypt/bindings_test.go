package encrypt_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

func emailPlan() *record.Plan {
	return &record.Plan{
		Context: []string{"users"},
		Fields: []record.Field{
			{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}},
		},
	}
}

// A binding ties each field to its row. It is in the stored context, after
// the scopes, so the row opens only through a cipher with the same binding.
// It is in no query context, so a query by the scopes alone derives the
// stored term, and a query through a cipher with a binding is refused.
func TestABindingIsInTheStoredContextOnly(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	plan := emailPlan()
	rows := []record.Source{{"email": "ada@example.com"}}
	bound := client.DefaultKeyset().Scope(uint64(42)).Bind(uint64(9))
	sealed, err := bound.Seal(ctx, plan, rows)
	if err != nil {
		t.Fatal(err)
	}

	// The contexts the cipher shows: the binding after the scope, in the
	// stored context only.
	shown, err := bound.Contexts(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	want := "email\n  query context:  (users / email) / 42u64\n  stored context: ((users / email) / 42u64) / 9u64\n"
	if shown != want {
		t.Fatalf("contexts:\n%s\nwant:\n%s", shown, want)
	}

	// The same scope with no binding derives the stored term: the binding
	// is not in the query context.
	query, err := client.DefaultKeyset().Scope(uint64(42)).QueryTerm(ctx, plan, "email", "eq", "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(query.Terms) != 1 || !reflect.DeepEqual(query.Terms[0], sealed[0]["email"].Terms[record.Equality]) {
		t.Fatal("a query by the scope alone does not derive the stored term")
	}

	// A query through a cipher with a binding is refused before any key is
	// requested.
	if _, err := bound.QueryTerm(ctx, plan, "email", "eq", "ada@example.com"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a query with a binding: %v", err)
	}

	// The row opens under the same binding, and under no other.
	opened, err := bound.Open(ctx, plan, sealed)
	if err != nil || !reflect.DeepEqual(opened, rows) {
		t.Fatalf("open: %v %v", err, opened)
	}
	if _, err := client.DefaultKeyset().Scope(uint64(42)).Bind(uint64(10)).Open(ctx, plan, sealed); err == nil {
		t.Fatal("a row opened under another binding")
	}
	if _, err := client.DefaultKeyset().Scope(uint64(42)).Open(ctx, plan, sealed); err == nil {
		t.Fatal("a row opened with its binding left out")
	}

	// Extend is Scope under its former name.
	if !reflect.DeepEqual(client.DefaultKeyset().Extend(uint64(42)).Scopes(), []any{uint64(42)}) {
		t.Fatal("Extend is not Scope")
	}
	if !reflect.DeepEqual(bound.Bindings(), []any{uint64(9)}) {
		t.Fatalf("bindings: %v", bound.Bindings())
	}
}

// An empty binding would bind every row to one context: a row ID not yet
// assigned. The cipher refuses it on the first call through it, before any
// key is requested, as the typed Rust path does.
func TestAnEmptyBindingIsRefused(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	plan := emailPlan()
	rows := []record.Source{{"email": "ada@example.com"}}
	for name, part := range map[string]any{"text": "", "bytes": []byte{}} {
		bound := client.DefaultKeyset().Scope(uint64(42)).Bind(part)
		if _, err := bound.Seal(ctx, plan, rows); !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("an empty %s binding sealed: %v", name, err)
		}
		if _, err := bound.Open(ctx, plan, nil); !errors.Is(err, encrypt.ErrEncoding) {
			t.Fatalf("an empty %s binding opened: %v", name, err)
		}
	}
	// The plan-level refusal, for a plan built by hand.
	withEmpty := emailPlan()
	withEmpty.Bind = []any{""}
	if err := withEmpty.Validate(); err == nil {
		t.Fatal("a plan with an empty binding validated")
	}
}

// "bind" is a plan-level key, so no field may be called that: the plan is
// refused before the engine sees it.
func TestAFieldNamedBindIsRefused(t *testing.T) {
	p := &record.Plan{
		Context: []string{"users"},
		Fields:  []record.Field{{Name: "bind", Kind: record.String, Outputs: []record.Output{record.Ciphertext}}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a field named bind validated")
	}
}

// An EQL type stores its column alone, so a binding has no column to sit
// under: the plan is refused, as an extended one is.
func TestABindingIsRefusedOnAnEQLType(t *testing.T) {
	p := &record.Plan{
		Context: []string{"users"},
		Bind:    []any{uint64(9)},
		Fields:  []record.Field{{Name: "email", Kind: record.String, Target: "TextEq"}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a bound EQL plan validated")
	}
}

// A byte-slice part is copied when the cipher takes it: a caller that
// reuses or changes its buffer afterwards does not change the context of
// a cipher it already has, so the row it sealed still opens through it.
func TestAByteSlicePartIsCopied(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	plan := emailPlan()
	rows := []record.Source{{"email": "ada@example.com"}}
	id := []byte("row-9")
	tenant := []byte("acme")
	bound := client.DefaultKeyset().Scope(tenant).Bind(id)
	sealed, err := bound.Seal(ctx, plan, rows)
	if err != nil {
		t.Fatal(err)
	}
	copy(id, "row-1")
	copy(tenant, "evil")
	if !reflect.DeepEqual(bound.Bindings(), []any{[]byte("row-9")}) {
		t.Fatalf("the binding changed with the caller's buffer: %v", bound.Bindings())
	}
	if !reflect.DeepEqual(bound.Scopes(), []any{[]byte("acme")}) {
		t.Fatalf("the scope changed with the caller's buffer: %v", bound.Scopes())
	}
	// A returned part is a copy too: changing it does not change the cipher.
	copy(bound.Bindings()[0].([]byte), "row-1")
	copy(bound.Scopes()[0].([]byte), "evil")
	if !reflect.DeepEqual(bound.Bindings(), []any{[]byte("row-9")}) {
		t.Fatalf("the binding changed through a returned part: %v", bound.Bindings())
	}
	if !reflect.DeepEqual(bound.Scopes(), []any{[]byte("acme")}) {
		t.Fatalf("the scope changed through a returned part: %v", bound.Scopes())
	}
	opened, err := bound.Open(ctx, plan, sealed)
	if err != nil || !reflect.DeepEqual(opened, rows) {
		t.Fatalf("open through the same cipher: %v %v", err, opened)
	}
}
