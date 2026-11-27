package encrypt

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// A cipher that holds a refusal reports it from every call that returns an
// error, KeysetID included, and before the guest is asked: the
// uninitialised instance would answer ErrState.
func TestEveryCallReportsTheCiphersStoredError(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	refused := map[string]*Cipher{
		"Keyset(nil)":                 c.Keyset(nil),
		"Keyset(nil).Scope":           c.Keyset(nil).Scope("tenant-42"),
		"Keyset(nil).Bind":            c.Keyset(nil).Bind("row-1"),
		"Keyset(nil).Audit":           c.Keyset(nil).Audit(NewAuditMetadata().Text("service", "billing")),
		"a scope the codec refuses":   c.DefaultKeyset().Scope(1.5),
		"an empty binding":            c.DefaultKeyset().Bind(""),
		"a context that is no label":  c.DefaultKeyset().Context("tenants//acme"),
		"audit metadata it refuses":   c.DefaultKeyset().Audit(NewAuditMetadata().Text("service", "\xff")),
		"a named keyset with a scope": c.Keyset(KeysetName("acme")).Scope(1.5),
	}
	plan := usersPlan()
	read := vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: "$.name"}}
	for name, cph := range refused {
		calls := map[string]func() error{
			"KeysetID":  func() error { _, err := cph.KeysetID(ctx); return err },
			"Contexts":  func() error { _, err := cph.Contexts(ctx, plan); return err },
			"Seal":      func() error { _, err := cph.Seal(ctx, plan, []record.Source{usersRow(1, "a@b.c")}); return err },
			"Open":      func() error { _, err := cph.Open(ctx, plan, []record.Sealed{fixtureRecord()}); return err },
			"QueryTerm": func() error { _, err := cph.QueryTerm(ctx, plan, "age", "eq", uint32(34)); return err },
			"Verify":    func() error { _, err := cph.Verify(ctx, plan, "email", "matches", "alice", []any{"alice"}); return err },
			"TargetLimit": func() error {
				_, err := cph.TargetLimit(ctx, plan, "email", "matches", []byte{1}, 1, Stats{})
				return err
			},
			"JSONOpen": func() error { _, err := cph.JSONOpen(ctx, plan, "email", read, nil); return err },
		}
		for method, call := range calls {
			err := call()
			if !errors.Is(err, ErrEncoding) || !errors.Is(err, cph.err) {
				t.Errorf("%s: %s: %v, want the cipher's stored error %v", name, method, err, cph.err)
			}
		}
	}
}

// KeysetID on Client.Keyset(nil) is refused, and does not answer with the
// default keyset's id: a caller that validates a tenant's keyset at boot
// with KeysetID would otherwise believe it holds one.
func TestKeysetIDOfANilSelectorIsRefused(t *testing.T) {
	ctx := context.Background()
	c, err := NewDeterministicClient(ctx, [32]byte{})
	if errors.Is(err, ErrDeterministicGuestNotBuilt) || errors.Is(err, ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.DefaultKeyset().KeysetID(ctx); err != nil {
		t.Fatalf("the default keyset: %v", err)
	}
	id, err := c.Keyset(nil).KeysetID(ctx)
	if !errors.Is(err, ErrEncoding) || id != (KeysetID{}) {
		t.Fatalf("Keyset(nil).KeysetID = %v, %v; want ErrEncoding and no id", id, err)
	}
}
