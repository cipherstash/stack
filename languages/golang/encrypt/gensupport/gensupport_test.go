package gensupport

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRedactedHidesSealedFieldsAndSortsShown(t *testing.T) {
	got := Redacted("EncryptedUser", map[string]any{"Nickname": "nick", "ID": int64(7)}, "Email", "Name")
	want := "EncryptedUser{ID: 7, Nickname: nick, Email: [sealed], Name: [sealed]}"
	if got != want {
		t.Fatalf("Redacted = %q, want %q", got, want)
	}
	if got := Redacted("EncryptedDocument", nil, "Sealed"); got != "EncryptedDocument{Sealed: [sealed]}" {
		t.Fatalf("Redacted with no shown fields = %q", got)
	}
}

func TestRedactedLogHidesSealedFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: dropTime}))
	logger.Info("saved", "user", RedactedLog(map[string]any{"ID": 7}, "Email"))
	line := buf.String()
	if !strings.Contains(line, "user.ID=7") || !strings.Contains(line, "user.Email=[sealed]") {
		t.Fatalf("log line = %q", line)
	}
}

func dropTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

func TestNoticesPrintOnceForEachType(t *testing.T) {
	var buf bytes.Buffer
	prev := SetNotices(&buf)
	defer SetNotices(prev)
	ResetNoticed()

	NoticeUntagged("Account", []string{"cache"})
	NoticeUntagged("Account", []string{"cache"})
	NoticeUntagged("Other", []string{"a", "b"})
	NoticeUntagged("Empty", nil)
	NoticePrintsPlaintext("User")
	NoticePrintsPlaintext("User")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d notices, want 3:\n%s", len(lines), buf.String())
	}
	if want := `stashgen: Account: not encrypted and not stored: the unexported field "cache". Tag it ` + "`stash:\"-\"`" + ` to confirm that.`; lines[0] != want {
		t.Fatalf("line 0 = %q\nwant     %q", lines[0], want)
	}
	if !strings.Contains(lines[1], `fields "a" and "b". Tag each`) {
		t.Fatalf("line 1 = %q", lines[1])
	}
	if !strings.Contains(lines[2], "User prints its sealed fields in the clear") {
		t.Fatalf("line 2 = %q", lines[2])
	}
}

func TestVersionConstantIsTyped(t *testing.T) {
	// A generated file holds `const _ = gensupport.GeneratedVersion2`. The
	// constant's type is unexported, so no other package can declare a value
	// that satisfies the same reference.
	accepts := func(generatedVersion) {}
	accepts(GeneratedVersion2)
	if GeneratedVersion2 != 2 {
		t.Fatalf("GeneratedVersion2 = %d", GeneratedVersion2)
	}
}

// Deref is how generated code passes a field declared over a pointer, and
// it is why a nil pointer never reaches the codec typed: the untyped nil it
// gives is == nil, so Seal leaves a null=sql field out and the engine sees a
// plain null elsewhere, while the typed nil itself is not == nil and would be
// sent as a typed null of the pointer's type (see encrypt's typed_nil_test).
func TestDerefGivesAnUntypedNilForANilPointer(t *testing.T) {
	// The contrast Deref exists for: the same pointer, as an interface
	// value, is not == nil. (Through a call, so the checker does not fold
	// the comparison away.)
	asAny := func(v any) any { return v }
	if asAny((*int64)(nil)) == nil {
		t.Fatal("a typed nil pointer is == nil as an interface; this test pins the opposite")
	}
	if v := Deref((*int64)(nil)); v != nil {
		t.Fatalf("Deref((*int64)(nil)) = %#v, want an untyped nil", v)
	}
	if v := Deref((*time.Time)(nil)); v != nil {
		t.Fatalf("Deref((*time.Time)(nil)) = %#v, want an untyped nil", v)
	}
	n, when := int64(7), time.Unix(1_700_000_000, 0).UTC()
	if v := Deref(&n); v != int64(7) {
		t.Fatalf("Deref(&7) = %#v, want the int64 7", v)
	}
	if v := Deref(&when); v != when {
		t.Fatalf("Deref(&when) = %#v, want the time", v)
	}
}
