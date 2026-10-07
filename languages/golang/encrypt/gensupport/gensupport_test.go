package gensupport

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
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
	// A generated file holds `const _ = gensupport.GeneratedVersion1`. The
	// constant's type is unexported, so no other package can declare a value
	// that satisfies the same reference.
	accepts := func(generatedVersion) {}
	accepts(GeneratedVersion1)
	if GeneratedVersion1 != 1 {
		t.Fatalf("GeneratedVersion1 = %d", GeneratedVersion1)
	}
}
