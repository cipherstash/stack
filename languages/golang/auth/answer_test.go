package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// When the answer of an auth guest is not an object, the error is
// ErrInternal. The error names the export and the kind of value that the
// answer is. The error never contains the value, because the value can be a
// key or a token.
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
		want := "cipherstash: internal guest failure: cannot read the guest's answer from sa_token: it is " + tc.kind + ", not an object. The cause is a bug, or a guest that does not match the version of this module"
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
	if fields, err := object("sa_token", encoded); err != nil || len(fields.obj) != 1 {
		t.Fatalf("an object: %v, %v", fields, err)
	}
	if _, err := object("sa_token", []byte{0xff}); !errors.Is(err, ErrInternal) ||
		!strings.Contains(err.Error(), "cannot read the guest's answer from sa_token") ||
		!strings.Contains(err.Error(), "does not match the version of this module") {
		t.Errorf("bytes that do not decode: %v", err)
	}
}

// The workspace list and the runnable operations are read the same way.
// For an answer that does not decode, or that is not what the export
// writes, the error names the export. The error also names the kind of
// value that the answer is.
func TestListAnswersNameTheExportAndTheirKind(t *testing.T) {
	marshal := func(v any) []byte {
		out, err := vcffi.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		read   func([]byte) error
		answer []byte
		want   string
	}{
		{func(b []byte) error { _, err := workspaceIDs(b); return err }, []byte{0xff}, "cannot read the guest's answer from sa_list_workspaces: "},
		{func(b []byte) error { _, err := workspaceIDs(b); return err }, marshal("secret"), "from sa_list_workspaces: it is a string, not a list"},
		{func(b []byte) error { _, err := workspaceIDs(b); return err }, marshal([]any{"ws", int64(1)}), "from sa_list_workspaces: workspace id 1 is a number, not a string"},
		{func(b []byte) error { _, err := decodeRunnable(b); return err }, []byte{0xff}, "cannot read the guest's answer from sa_auth_runnable: "},
		{func(b []byte) error { _, err := decodeRunnable(b); return err }, marshal("secret"), "from sa_auth_runnable: it is a string, not a list"},
		{func(b []byte) error { _, err := decodeRunnable(b); return err }, marshal([]any{uint64(1), "secret"}), "from sa_auth_runnable: operation 1 is a string, not a handle"},
	} {
		err := tc.read(tc.answer)
		if !errors.Is(err, ErrInternal) || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret") {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
	if ids, err := workspaceIDs(marshal([]any{"a", "b"})); err != nil || len(ids) != 2 {
		t.Errorf("a good list: %v, %v", ids, err)
	}
	if handles, err := decodeRunnable(marshal([]any{uint64(3)})); err != nil || len(handles) != 1 || handles[0] != 3 {
		t.Errorf("good handles: %v, %v", handles, err)
	}
}

// When a field of an answer is missing or is of the wrong kind, the error
// is ErrInternal. The error names the export and the field. The error says
// that the cause is a bug, or a guest of another version. The error never
// contains the value of the field, because the value can be a token or a
// key.
func TestAnAnswersFieldsNameTheExport(t *testing.T) {
	answer := fields{export: "sa_token", obj: vcvalue.Object{
		{Key: "access_token", Value: int64(7)},
		{Key: "client_key", Value: "secret-key"},
		{Key: "region", Value: []byte("secret")},
		{Key: "expires_at", Value: "secret"},
	}}
	for _, tc := range []struct {
		read func() error
		want string
	}{
		{func() error { _, err := answer.text("token_type"); return err }, "it has no token_type"},
		{func() error { _, err := answer.text("access_token"); return err }, "access_token is a number, not a string"},
		{func() error { _, err := answer.bytes("missing"); return err }, "it has no missing"},
		{func() error { _, err := answer.bytes("client_key"); return err }, "client_key is a string, not bytes"},
		{func() error { _, err := answer.optionalText("region"); return err }, "region is bytes, not a string"},
		{func() error { _, err := answer.uint64Field("missing"); return err }, "it has no missing"},
		{func() error { _, err := answer.uint64Field("expires_at"); return err }, "expires_at is a string, not an unsigned integer"},
	} {
		err := tc.read()
		want := "cipherstash: internal guest failure: cannot read the guest's answer from sa_token: " + tc.want + ". The cause is a bug, or a guest that does not match the version of this module"
		if !errors.Is(err, ErrInternal) || err == nil || err.Error() != want {
			t.Errorf("message:\n got %v\nwant %q", err, want)
		}
	}
	if s, err := answer.optionalText("absent"); err != nil || s != "" {
		t.Errorf("an absent optional field: %q, %v", s, err)
	}
}

// The error for a step that this package cannot read names sa_auth_io.
func TestAStepThatDoesNotReadNamesTheExport(t *testing.T) {
	for _, raw := range [][]byte{{0xff}, mustMarshalAuth(t, "secret")} {
		_, err := decodeAuthStep(raw)
		if !errors.Is(err, ErrInternal) || !errors.Is(err, errStepMalformed) ||
			!strings.Contains(err.Error(), "cannot read the guest's answer from sa_auth_io: the step is malformed") ||
			strings.Contains(err.Error(), "secret") {
			t.Errorf("%x: %v", raw, err)
		}
	}
}

func mustMarshalAuth(t *testing.T, v any) []byte {
	t.Helper()
	out, err := vcffi.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
