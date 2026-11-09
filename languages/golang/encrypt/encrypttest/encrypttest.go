// Package encrypttest holds assertions for tests of code that uses package
// encrypt and its generated records.
//
// A wrong context loses data silently. A query under the wrong context
// matches nothing, and gives no error. [AssertContexts] pins the contexts
// of a generated record's fields. A change to them then fails the build.
// The text it compares is the engine's. A Rust record's contexts() prints
// the same text for the same declaration.
package encrypttest

import (
	"context"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
)

// Contexts asks the embedded engine for the contexts of the declaration's
// fields. The text has one line per field, then one indented line with its
// context: "email\n  context: users / email\n". It needs no credentials
// and no network.
func Contexts(ctx context.Context, d gensupport.Declaration) (string, error) {
	checker, err := encrypt.NewChecker(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = checker.Close() }()
	return d.Contexts(ctx, checker)
}

// AssertContexts fails the test when the declaration's contexts are not
// `want`. The failure names the first line that differs. The lines are the
// ones [Contexts] prints. A trailing newline on `want` is optional.
//
//	encrypttest.AssertContexts(t, declaration,
//		"email\n  context: users / email\n"+
//			"age\n  context: users / age\n")
func AssertContexts(tb testing.TB, d gensupport.Declaration, want string) {
	tb.Helper()
	got, err := Contexts(context.Background(), d)
	if err != nil {
		tb.Fatalf("encrypttest: the engine refused the declaration: %v", err)
	}
	gotLines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	wantLines := strings.Split(strings.TrimSuffix(want, "\n"), "\n")
	for i := range min(len(gotLines), len(wantLines)) {
		if gotLines[i] != wantLines[i] {
			tb.Fatalf("encrypttest: the contexts differ at line %d:\n  want: %q\n  got:  %q\nall contexts:\n%s", i+1, wantLines[i], gotLines[i], got)
		}
	}
	if len(gotLines) != len(wantLines) {
		tb.Fatalf("encrypttest: the contexts have %d lines, and %d were expected:\n%s", len(gotLines), len(wantLines), got)
	}
}
