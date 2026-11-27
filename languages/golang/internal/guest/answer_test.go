package guest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// KindOf names a decoded value by its kind, never its value.
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
		{struct{ secret string }{"secret"}, "a single value"},
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
}
