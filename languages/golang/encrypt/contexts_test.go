package encrypt_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

func usersPlan() *record.Plan {
	return &record.Plan{
		Context: []string{"users"},
		Fields: []record.Field{
			{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}},
			{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Ore}},
		},
	}
}

// The checker shows each sealed field under the record's name and the
// field's name, as the Rust record derive does for the same declaration. A
// passthrough field stays on the host, so it is not in the plan and not
// shown.
func TestCheckerContextsShowEachSealedField(t *testing.T) {
	wasm, err := encrypt.EmbeddedGuest()
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
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
	defer func() { _ = checker.Close() }()

	got, err := checker.Contexts(ctx, usersPlan())
	if err != nil {
		t.Fatal(err)
	}
	want := "email\n  context: users / email\nage\n  context: users / age\n"
	if got != want {
		t.Fatalf("contexts:\n%s\nwant:\n%s", got, want)
	}

	// A plan whose context is a field of each record shows where the
	// context is read from.
	byField := &record.Plan{
		ContextField: "tenant",
		Fields: []record.Field{
			{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality}},
		},
	}
	got, err = checker.Contexts(ctx, byField)
	if err != nil {
		t.Fatal(err)
	}
	want = "email\n  context: {tenant: Label, from the plaintext} / email\n"
	if got != want {
		t.Fatalf("contexts:\n%s\nwant:\n%s", got, want)
	}

	// A plan the engine refuses is refused here too: a match index on an
	// integer.
	bad := &record.Plan{Context: []string{"users"}, Fields: []record.Field{
		{Name: "age", Kind: record.Uint32, Outputs: []record.Output{record.Ciphertext, record.Match}},
	}}
	if _, err := checker.Contexts(ctx, bad); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a refused plan: %v", err)
	}
}

// A cipher shows the contexts with its extension applied: each part extends
// the field's context, in order, nesting to the left.
func TestCipherContextsApplyTheExtension(t *testing.T) {
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte{})
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	plain, err := client.DefaultKeyset().Contexts(ctx, usersPlan())
	if err != nil {
		t.Fatal(err)
	}
	if want := "email\n  context: users / email\nage\n  context: users / age\n"; plain != want {
		t.Fatalf("contexts:\n%s\nwant:\n%s", plain, want)
	}
	extended, err := client.DefaultKeyset().Extend(uint64(7), "eu").Contexts(ctx, usersPlan())
	if err != nil {
		t.Fatal(err)
	}
	want := "email\n  context: ((users / email) / 7u64) / eu\nage\n  context: ((users / age) / 7u64) / eu\n"
	if extended != want {
		t.Fatalf("contexts:\n%s\nwant:\n%s", extended, want)
	}
}
