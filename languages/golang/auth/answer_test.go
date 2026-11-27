package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// An auth guest's answer that is not an object is an internal failure that
// names the export and says what the answer is, by its kind: never its
// value, which can be a key or a token.
func TestAnAnswerThatIsNotAnObjectNamesTheExportAndItsKind(t *testing.T) {
	for _, tc := range []struct {
		answer any
		kind   string
	}{
		{[]any{"secret-token"}, "a list"},
		{"secret-token", "a string"},
		{[]byte("secret-key"), "bytes"},
	} {
		encoded, err := vcffi.Marshal(tc.answer)
		if err != nil {
			t.Fatal(err)
		}
		_, err = object("sa_token", encoded)
		if !errors.Is(err, ErrInternal) {
			t.Fatalf("%s: %v, want ErrInternal", tc.kind, err)
		}
		want := "cipherstash: internal guest failure: the guest's answer to sa_token does not read: it is " + tc.kind + ", not an object; this is a bug, or a guest that does not match this module's version"
		if err.Error() != want {
			t.Errorf("message:\n got %q\nwant %q", err.Error(), want)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("the error holds the answer: %v", err)
		}
	}
	encoded, err := vcffi.Marshal(vcvalue.Object{{Key: "access_token", Value: "t"}})
	if err != nil {
		t.Fatal(err)
	}
	if fields, err := object("sa_token", encoded); err != nil || len(fields) != 1 {
		t.Fatalf("an object: %v, %v", fields, err)
	}
	if _, err := object("sa_token", []byte{0xff}); !errors.Is(err, ErrInternal) || !strings.Contains(err.Error(), "sa_token") {
		t.Errorf("bytes that do not decode: %v", err)
	}
}
