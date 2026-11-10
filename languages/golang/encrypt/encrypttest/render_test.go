package encrypttest

import "testing"

// Each kind of part renders as stack-encrypt's `contexts.rs` prints it, so
// a Go test and a Rust test state the same context in the same words. The
// expected strings are the ones its unit tests pin.
func TestPartsRenderAsTheEnginePrintsThem(t *testing.T) {
	cases := []struct {
		name  string
		parts []any
		want  string
	}{
		{"two text parts are a bare list", []any{"users", "email"}, "users / email"},
		{"one text part is that part", []any{"users"}, "users"},
		{"a nested list is in parentheses", []any{List{"settings", "theme"}, List{"accounts", "owner"}}, "(settings / theme) / (accounts / owner)"},
		{"a list of one part is in parentheses", []any{List{"email"}}, "(email)"},
		{"a list under a part", []any{List{"users", "email"}, uint64(7)}, "(users / email) / 7u64"},
		{"every width has its suffix", []any{uint8(1), uint16(2), uint32(3), uint64(4), int8(-1), int16(-2), int32(-3), int64(-4)}, "1u8 / 2u16 / 3u32 / 4u64 / -1i8 / -2i16 / -3i32 / -4i64"},
		{"bytes are hex", []any{[]byte{0x37, 0xab}}, "0x37ab"},
		{"text with a separator is quoted", []any{"users/email"}, `"users/email"`},
		{"text that reads as a placeholder is quoted", []any{"{context: u64}"}, `"{context: u64}"`},
		{"a quote and a backslash in quoted text take a backslash", []any{`a/b"c\d`}, `"a/b\"c\\d"`},
		{"a quote in plain text is plain", []any{`a"b`}, `a"b`},
		{"a control character is its code point", []any{"a\tb"}, `"a\u{9}b"`},
		{"a zero-width space is its code point", []any{"a\u200bb"}, `"a\u{200b}b"`},
		{"the extension placeholder", []any{List{"users", "email"}, Extension()}, "(users / email) / {extension?: CallerContext}"},
		{"a required placeholder", []any{Required("NonEmpty<String>")}, "{context: NonEmpty<String>}"},
		{"an optional placeholder", []any{Optional("u64")}, "{context?: u64}"},
		{"a placeholder from the plaintext", []any{List{FromPlaintext("tenant", "Label"), "email"}, Extension()}, "({tenant: Label, from the plaintext} / email) / {extension?: CallerContext}"},
	}
	for _, c := range cases {
		got, err := renderContext(c.parts)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n  want: %s\n  got:  %s", c.name, c.want, got)
		}
	}
}

func TestAPartTheEngineHasNoWordForIsRefused(t *testing.T) {
	for _, parts := range [][]any{
		{},
		{7},
		{uint(7)},
		{3.5},
		{List{}},
	} {
		if _, err := renderContext(parts); err == nil {
			t.Errorf("%v rendered", parts)
		}
	}
}

func TestTheEnginesTextIsReadBackFieldByField(t *testing.T) {
	fields, err := parse("email\n  context: users / email\nnotes\n  context: users / notes\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields[0] != (fieldText{"email", "users / email"}) || fields[1] != (fieldText{"notes", "users / notes"}) {
		t.Fatalf("fields: %+v", fields)
	}
	fields, err = parse("no field is sealed or indexed\n")
	if err != nil || len(fields) != 0 {
		t.Fatalf("no field: %+v, %v", fields, err)
	}
	for _, text := range []string{
		"email\n",
		"email\ncontext: users / email\n",
		"  email\n  context: users / email\n",
	} {
		if _, err := parse(text); err == nil {
			t.Errorf("%q parsed", text)
		}
	}
}
