package encrypttest_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/encrypttest"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
)

// recorder is a testing.TB whose Fatalf records the message instead of
// stopping the test, so the failure text of AssertContexts can be checked.
type recorder struct {
	testing.TB
	failed string
}

func (r *recorder) Helper() {}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = strings.TrimSpace(fmt.Sprintf(format, args...))
}

func users() gensupport.Declaration {
	return gensupport.Declare("users").
		EncryptIndex("email", gensupport.String, encrypt.Equality).
		Encrypt("notes", gensupport.String)
}

func skipWithoutGuest(t *testing.T) {
	t.Helper()
	if _, err := encrypttest.Contexts(context.Background(), users()); errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
}

func TestAssertContextsPassesOnTheEnginesContexts(t *testing.T) {
	skipWithoutGuest(t)
	encrypttest.AssertContexts(t, users(),
		encrypttest.Field("email", "users", "email"),
		encrypttest.Field("notes", "users", "notes"),
	)
	// The text itself is still there for a test that wants it whole.
	text, err := encrypttest.Contexts(context.Background(), users())
	if err != nil {
		t.Fatal(err)
	}
	if text != "email\n  context: users / email\nnotes\n  context: users / notes\n" {
		t.Fatalf("text: %q", text)
	}
}

func TestAssertContextsNamesTheFirstFieldThatDiffers(t *testing.T) {
	skipWithoutGuest(t)
	r := &recorder{TB: t}
	encrypttest.AssertContexts(r, users(),
		encrypttest.Field("email", "users", "email"),
		encrypttest.Field("notes", "users", "name"),
	)
	if !strings.Contains(r.failed, `the context of "notes" differs`) ||
		!strings.Contains(r.failed, "want: users / name") ||
		!strings.Contains(r.failed, "got:  users / notes") {
		t.Fatalf("failure text: %q", r.failed)
	}

	r = &recorder{TB: t}
	encrypttest.AssertContexts(r, users(),
		encrypttest.Field("email", "users", "email"),
		encrypttest.Field("memo", "users", "notes"),
	)
	if !strings.Contains(r.failed, `field 2 is "notes", and "memo" was stated`) {
		t.Fatalf("failure text: %q", r.failed)
	}

	r = &recorder{TB: t}
	encrypttest.AssertContexts(r, users(), encrypttest.Field("email", "users", "email"))
	if !strings.Contains(r.failed, "has 2 fields with a context, and 1 were stated") {
		t.Fatalf("failure text: %q", r.failed)
	}

	// A nested list of one part is in parentheses, where the engine's text
	// is bare, so the shape of a context is checked as well as its parts.
	r = &recorder{TB: t}
	encrypttest.AssertContexts(r, users(),
		encrypttest.Field("email", encrypttest.List{"users"}, "email"),
		encrypttest.Field("notes", "users", "notes"),
	)
	if !strings.Contains(r.failed, "want: (users) / email") {
		t.Fatalf("failure text: %q", r.failed)
	}

	// One list at the top of a context is the context: the same as its
	// parts written out.
	encrypttest.AssertContexts(t, users(),
		encrypttest.Field("email", encrypttest.List{"users", "email"}),
		encrypttest.Field("notes", "users", "notes"),
	)
}

func TestAssertContextsReportsARefusedDeclaration(t *testing.T) {
	skipWithoutGuest(t)
	bad := gensupport.Declare("users").EncryptIndex("age", gensupport.Uint32, encrypt.Match())
	r := &recorder{TB: t}
	encrypttest.AssertContexts(r, bad)
	if !strings.Contains(r.failed, "the engine refused the declaration") {
		t.Fatalf("failure text: %q", r.failed)
	}
}
