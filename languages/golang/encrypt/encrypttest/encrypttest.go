// Package encrypttest holds assertions for tests of code that uses package
// encrypt and its generated records.
//
// A wrong context loses data silently. A query under the wrong context
// matches nothing, and gives no error. [AssertContexts] pins the contexts
// of a generated record's fields, one [Field] per field, in order. A change
// to them then fails the build. The parts a test states render as the
// engine prints them, so a Rust test of the same declaration states the
// same parts with stack-encrypt's assert_context! macro.
package encrypttest

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Contexts asks the embedded engine for the contexts of the declaration's
// fields. The text has one line per field, then one indented line with its
// context: "email\n  context: users / email\n". It needs no credentials
// and no network. [AssertContexts] reads this text; a test that wants the
// text itself, to print or to compare whole, calls this.
func Contexts(ctx context.Context, d gensupport.Declaration) (string, error) {
	checker, err := encrypt.NewChecker(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = checker.Close() }()
	return d.Contexts(ctx, checker)
}

// A FieldContext is the context of one field, as a test states it: the
// field's name and the parts of its context, in order. Build one with
// [Field].
type FieldContext struct {
	Name  string
	Parts []any
}

// Field states the context of the field `name` as its parts, in order. A
// part is one of:
//
//   - a string, a text part;
//   - an integer of a fixed width (uint8 to uint64, int8 to int64), an
//     integer part of that width;
//   - a []byte, a bytes part;
//   - a [List], a nested list of parts;
//   - a [Placeholder], a part the caller supplies when the record is
//     encrypted, such as [Extension].
//
// Two or more parts are the list the context is. One part is that part.
//
//	encrypttest.Field("email", "users", "email")
func Field(name string, parts ...any) FieldContext {
	return FieldContext{Name: name, Parts: parts}
}

// A List is a nested list of parts inside a context: a record's own context
// nested under its outer record's, for example. At the top of a context,
// the parts of [Field] are already a list.
type List []any

// A Placeholder is a part of a context that the caller supplies when the
// record is encrypted, named and typed as the engine prints it:
// "{name: Type}", or "{name?: Type}" when it is optional, with ", from the
// plaintext" when it is read from a field of the value.
type Placeholder struct {
	Name          string
	Type          string
	Optional      bool
	FromPlaintext bool
}

// Extension is the optional extension a plan accepts from the call that
// runs it: "{extension?: CallerContext}".
func Extension() Placeholder {
	return Placeholder{Name: "extension", Type: "CallerContext", Optional: true}
}

// Required is a part of type `typ` the caller must supply:
// "{context: typ}".
func Required(typ string) Placeholder {
	return Placeholder{Name: "context", Type: typ}
}

// Optional is a part of type `typ` the caller may supply:
// "{context?: typ}".
func Optional(typ string) Placeholder {
	return Placeholder{Name: "context", Type: typ, Optional: true}
}

// FromPlaintext is a part of type `typ` read from the field `name` of the
// plaintext: "{name: typ, from the plaintext}".
func FromPlaintext(name, typ string) Placeholder {
	return Placeholder{Name: name, Type: typ, FromPlaintext: true}
}

// AssertContexts fails the test when the declaration's fields and their
// contexts are not `want`, in order. The failure names the first field that
// differs, or the first field whose context differs, with both contexts as
// the engine prints them.
//
//	encrypttest.AssertContexts(t, declaration,
//		encrypttest.Field("email", "users", "email"),
//		encrypttest.Field("age", "users", "age"),
//	)
func AssertContexts(tb testing.TB, d gensupport.Declaration, want ...FieldContext) {
	tb.Helper()
	got, err := Contexts(tb.Context(), d)
	if err != nil {
		tb.Fatalf("encrypttest: the engine refused the declaration: %v", err)
	}
	fields, err := parse(got)
	if err != nil {
		tb.Fatalf("encrypttest: the engine's text is not one field per line pair: %v\n%s", err, got)
	}
	for i := range min(len(fields), len(want)) {
		if fields[i].name != want[i].Name {
			tb.Fatalf("encrypttest: field %d is %q, and %q was stated\nall contexts:\n%s", i+1, fields[i].name, want[i].Name, got)
		}
		wanted, err := renderContext(want[i].Parts)
		if err != nil {
			tb.Fatalf("encrypttest: the context stated for %q cannot be rendered: %v", want[i].Name, err)
		}
		if fields[i].context != wanted {
			tb.Fatalf("encrypttest: the context of %q differs:\n  want: %s\n  got:  %s\nall contexts:\n%s", want[i].Name, wanted, fields[i].context, got)
		}
	}
	if len(fields) != len(want) {
		tb.Fatalf("encrypttest: the declaration has %d fields with a context, and %d were stated\nall contexts:\n%s", len(fields), len(want), got)
	}
}

// fieldText is one field as the engine prints it.
type fieldText struct {
	name    string
	context string
}

// parse reads the engine's text back: pairs of a field line and an
// indented context line, or the one line that says no field is sealed.
func parse(text string) ([]fieldText, error) {
	text = strings.TrimSuffix(text, "\n")
	if text == "" || text == "no field is sealed or indexed" {
		return nil, nil
	}
	lines := strings.Split(text, "\n")
	if len(lines)%2 != 0 {
		return nil, fmt.Errorf("%d lines", len(lines))
	}
	fields := make([]fieldText, 0, len(lines)/2)
	for i := 0; i < len(lines); i += 2 {
		name := lines[i]
		if name == "" || strings.HasPrefix(name, " ") {
			return nil, fmt.Errorf("line %d is not a field name: %q", i+1, name)
		}
		context, ok := strings.CutPrefix(lines[i+1], "  context: ")
		if !ok {
			return nil, fmt.Errorf("line %d is not a context: %q", i+2, lines[i+1])
		}
		fields = append(fields, fieldText{name: name, context: context})
	}
	return fields, nil
}

// renderContext renders the parts of one field's context as the engine
// prints a context: two or more parts joined by " / ", one part as itself.
func renderContext(parts []any) (string, error) {
	if len(parts) == 0 {
		return "", fmt.Errorf("a context has at least one part")
	}
	if len(parts) == 1 {
		return render(parts[0], false)
	}
	return renderList(parts, true)
}

// renderList renders parts joined by " / ". A nested list, or a list of one
// part, is in parentheses; the list at the top of a context is bare.
func renderList(parts []any, top bool) (string, error) {
	var b strings.Builder
	bare := top && len(parts) >= 2
	if !bare {
		b.WriteByte('(')
	}
	for i, part := range parts {
		if i > 0 {
			b.WriteString(" / ")
		}
		text, err := render(part, true)
		if err != nil {
			return "", err
		}
		b.WriteString(text)
	}
	if !bare {
		b.WriteByte(')')
	}
	return b.String(), nil
}

// render renders one part as the engine prints it. `nested` says the part
// is inside a list, where a list of its own is in parentheses.
func render(part any, nested bool) (string, error) {
	switch v := part.(type) {
	case string:
		return renderText(v), nil
	case []byte:
		return "0x" + hex.EncodeToString(v), nil
	case uint8:
		return fmt.Sprintf("%du8", v), nil
	case uint16:
		return fmt.Sprintf("%du16", v), nil
	case uint32:
		return fmt.Sprintf("%du32", v), nil
	case uint64:
		return fmt.Sprintf("%du64", v), nil
	case int8:
		return fmt.Sprintf("%di8", v), nil
	case int16:
		return fmt.Sprintf("%di16", v), nil
	case int32:
		return fmt.Sprintf("%di32", v), nil
	case int64:
		return fmt.Sprintf("%di64", v), nil
	case List:
		if len(v) == 0 {
			return "", fmt.Errorf("a list has at least one part")
		}
		return renderList(v, !nested)
	case Placeholder:
		var b strings.Builder
		b.WriteByte('{')
		b.WriteString(v.Name)
		if v.Optional {
			b.WriteByte('?')
		}
		b.WriteString(": ")
		b.WriteString(v.Type)
		if v.FromPlaintext {
			b.WriteString(", from the plaintext")
		}
		b.WriteByte('}')
		return b.String(), nil
	case int, uint:
		return "", fmt.Errorf("%T has no fixed width; state the part as the engine's type, such as uint64(%v)", v, v)
	default:
		return "", fmt.Errorf("%T is not a part of a context", v)
	}
}

// renderText renders a text part as the engine does: plain text as it is,
// and text that is not plain, or that would read as a placeholder or an
// encoded context, in quotes. The quoting is the engine's own: `"` and `\`
// take a backslash, and a control or non-printing character is `\u{..}`
// with its code point in hex.
func renderText(text string) string {
	readsAsAnotherForm := strings.HasPrefix(text, "{") || strings.HasPrefix(text, "encoded:")
	if record.CheckSegment(text) == nil && !readsAsAnotherForm {
		return text
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range text {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case unicode.IsControl(r) || !isPrinting(r):
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// isPrinting reports whether a character shows on its own: not a format
// character such as a zero-width or bidirectional mark, which would print
// as another name. The list is the engine's.
func isPrinting(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r == 0xFEFF:
		return false
	}
	return true
}
