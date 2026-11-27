package guest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// named is a Go type of its own over a string.
type named string

// KindOf names a decoded value by its kind, never its value: the vcvalue
// types by what they are, and any other Go value by its reflect.Kind.
func TestKindOfNamesAValueByItsKind(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  string
	}{
		{nil, "null"},
		{vcvalue.TypedNull{}, "null"},
		{vcvalue.Object{{Key: "secret", Value: "secret"}}, "an object"},
		{[]any{"secret"}, "a list"},
		{"secret", "a string"},
		{[]byte("secret"), "bytes"},
		{true, "a boolean"},
		{int8(1), "a number"},
		{int16(1), "a number"},
		{int32(1), "a number"},
		{int64(1), "a number"},
		{uint8(1), "a number"},
		{uint16(1), "a number"},
		{uint32(1), "a number"},
		{uint64(1), "a number"},
		{vcvalue.Int128{}, "a number"},
		{vcvalue.Uint128{}, "a number"},
		{float32(1), "a number"},
		{float64(1), "a number"},
		{vcvalue.Date{}, "a date"},
		{vcvalue.Timestamp{}, "a timestamp"},
		{vcvalue.Decimal{}, "a decimal"},
		{vcvalue.UUID{}, "a UUID"},
		{vcvalue.Sealed("secret"), "a sealed value"},
		{vcvalue.SealedEmptySeq("secret"), "a sealed empty list"},
		{vcvalue.SealedEmptyMap("secret"), "a sealed empty map"},
		{vcvalue.Plain{V: "secret"}, "a passthrough value"},
		{vcvalue.Tagged{ID: 200, V: "secret"}, "a value of a type this build does not know"},
		{int(1), "a number"},
		{uint(1), "a number"},
		{uintptr(1), "a number"},
		{named("secret"), "a string"},
		{[]int64{1}, "a list"},
		{[2]string{"secret"}, "a list"},
		{[4]byte{1}, "bytes"},
		{map[string]any{"secret": 1}, "a map"},
		{map[string]int64{"secret": 1}, "a map"},
		{struct{ secret string }{"secret"}, "a struct"},
		{new(int), "a pointer"},
		{func() {}, "a single value"},
		{make(chan int), "a single value"},
	} {
		if got := guest.KindOf(tc.value); got != tc.want {
			t.Errorf("KindOf(%T) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// A guest answer this module cannot read is an internal failure that names
// the export and what was wrong, and says it is not the caller's input.
func TestBadAnswerIsInternalAndNamesTheExport(t *testing.T) {
	err := guest.BadAnswer("se_query_term", errors.New("it is a list, not an object"))
	if !errors.Is(err, guest.ErrInternal) {
		t.Fatalf("%v is not ErrInternal", err)
	}
	want := "cipherstash: internal guest failure: the guest's answer to se_query_term does not read: it is a list, not an object; this is a bug, or a guest that does not match this module's version"
	if err.Error() != want {
		t.Errorf("message:\n got %q\nwant %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "malformed input") {
		t.Errorf("reads as bad input: %v", err)
	}
	// The problem is wrapped, so a caller can still match what is behind it.
	cause := errors.New("the decoder's error")
	if !errors.Is(guest.BadAnswer("se_targets", cause), cause) {
		t.Error("the problem is not wrapped")
	}
}

// DecodeAnswer decodes an answer, and refuses bytes that do not decode as
// an internal failure naming the export, wrapping the decoder's error.
func TestDecodeAnswerNamesTheExport(t *testing.T) {
	encoded, err := vcffi.Marshal("users / email")
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := guest.DecodeAnswer("se_contexts", encoded); err != nil || decoded != "users / email" {
		t.Errorf("a good answer: %v, %v", decoded, err)
	}
	_, err = guest.DecodeAnswer("se_contexts", []byte{0xff})
	if !errors.Is(err, guest.ErrInternal) ||
		!strings.HasPrefix(err.Error(), "cipherstash: internal guest failure: the guest's answer to se_contexts does not read: ") ||
		!strings.HasSuffix(err.Error(), "; this is a bug, or a guest that does not match this module's version") {
		t.Errorf("bytes that do not decode: %v", err)
	}
}
