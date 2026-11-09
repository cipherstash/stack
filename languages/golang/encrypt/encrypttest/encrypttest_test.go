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

func TestAssertContextsPassesOnTheEnginesText(t *testing.T) {
	skipWithoutGuest(t)
	encrypttest.AssertContexts(t, users(),
		"email\n  context: users / email\n"+
			"notes\n  context: users / notes\n")
	// A trailing newline is optional.
	encrypttest.AssertContexts(t, users(),
		"email\n  context: users / email\n"+
			"notes\n  context: users / notes")
}

func TestAssertContextsNamesTheFirstLineThatDiffers(t *testing.T) {
	skipWithoutGuest(t)
	r := &recorder{TB: t}
	encrypttest.AssertContexts(r, users(),
		"email\n  context: users / email\n"+
			"notes\n  context: users / name\n")
	if !strings.Contains(r.failed, "differ at line 4") || !strings.Contains(r.failed, `want: "  context: users / name"`) {
		t.Fatalf("failure text: %q", r.failed)
	}
	r = &recorder{TB: t}
	encrypttest.AssertContexts(r, users(), "email\n  context: users / email\n")
	if !strings.Contains(r.failed, "have 4 lines, and 2 were expected") {
		t.Fatalf("failure text: %q", r.failed)
	}
}

func TestAssertContextsReportsARefusedDeclaration(t *testing.T) {
	skipWithoutGuest(t)
	bad := gensupport.Declare("users").EncryptIndex("age", gensupport.Uint32, encrypt.Match())
	r := &recorder{TB: t}
	encrypttest.AssertContexts(r, bad, "")
	if !strings.Contains(r.failed, "the engine refused the declaration") {
		t.Fatalf("failure text: %q", r.failed)
	}
}
