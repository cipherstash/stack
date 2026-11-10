package encrypt

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// A record stores match text that cuts no token as the empty filter, so the
// term-failure locator must not blame a row for it. derive asks the query
// path, which refuses that text; the locator skips that refusal and goes on
// to the rows after it.
func TestLocateTermFailureSkipsShortMatchText(t *testing.T) {
	ctx := context.Background()
	c, err := NewDeterministicClient(ctx, [32]byte{})
	if errors.Is(err, ErrDeterministicGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cph := c.DefaultKeyset()
	plan := usersPlan()

	// The query path refuses the short email, so without the skip the
	// locator would name row 0 for it.
	_, derr := cph.derive(ctx, plan, "email", record.Match, "ab")
	if !queryOnlyRefusal(record.Match, derr) {
		t.Fatalf("derive of a short email: %v, want the empty-term-text refusal", derr)
	}

	sentinel := fmt.Errorf("%w: from the record call", ErrTerm)
	rows := []record.Source{usersRow(1, "ab"), usersRow(2, "alice@example.com")}
	if got := cph.locateTermFailure(ctx, plan, rows, sentinel); got != sentinel {
		t.Fatalf("locateTermFailure = %v, want the record call's error unchanged", got)
	}
}
