package stackencrypt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A label's string is its descriptor and reads back losslessly; as a
// context, one segment is the bare part, two are the pair With builds, and
// more are a flat list — the same shapes Rust's Label takes.
func TestLabelRendersAsItsDisplayAndBindsTheMatchingContext(t *testing.T) {
	pair, err := NewContext("users")
	if err != nil {
		t.Fatal(err)
	}
	if pair, err = pair.With("age"); err != nil {
		t.Fatal(err)
	}
	for text, want := range map[string]any{
		"users":             "users",
		"users/age":         []any{"users", "age"},
		"documents/v2/body": []any{"documents", "v2", "body"},
		"naïve/with space":  []any{"naïve", "with space"},
	} {
		l, err := ParseLabel(text)
		if err != nil {
			t.Fatalf("ParseLabel(%q): %v", text, err)
		}
		if l.String() != text {
			t.Errorf("ParseLabel(%q).String() = %q", text, l.String())
		}
		if got := l.Segments(); strings.Join(got, "/") != text {
			t.Errorf("ParseLabel(%q).Segments() = %q", text, got)
		}
		if got := l.Context().value(); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseLabel(%q).Context() = %#v, want %#v", text, got, want)
		}
		if again, err := NewLabel(l.Segments()...); err != nil || !reflect.DeepEqual(again, l) {
			t.Errorf("NewLabel(segments of %q) = %#v, %v", text, again, err)
		}
	}
	if got := label(t, "users/age").Context().value(); !reflect.DeepEqual(got, pair.value()) {
		t.Errorf("a two-segment label is not the With pair: %#v vs %#v", got, pair.value())
	}
	if got := label(t, "users").Context().value(); !reflect.DeepEqual(got, MustContext("users").value()) {
		t.Errorf("a one-segment label is not the bare part: %#v", got)
	}
	// A literal containing '/' is one part, not the pair: the two spell
	// different contexts, as in Rust.
	if reflect.DeepEqual(MustContext("users/age").value(), label(t, "users/age").Context().value()) {
		t.Error(`NewContext("users/age") and label(t, "users/age") bind the same context`)
	}
	if got := (Label{}).Context(); !got.isZero() {
		t.Errorf("zero Label's Context = %#v, want the zero Context", got)
	}
}

// Every way a segment is not plain is refused and named, matching Rust's
// LabelError variants: a label never renders escaped.
func TestLabelRefusesSegmentsThatWouldNotRenderVerbatim(t *testing.T) {
	if _, err := NewLabel(); !errors.Is(err, ErrEmptyLabel) {
		t.Errorf("NewLabel() = %v, want ErrEmptyLabel", err)
	}
	for _, tc := range []struct {
		segments []string
		index    int
		reason   string
	}{
		{[]string{""}, 0, "is empty"},
		{[]string{"users", ""}, 1, "is empty"},
		{[]string{"users", "a/b"}, 1, "separator"},
		{[]string{"b64:x"}, 0, "another descriptor form"},
		{[]string{"users", "7"}, 1, "another descriptor form"},
		{[]string{"-x"}, 0, "another descriptor form"},
		{[]string{"a(b"}, 0, "reserves"},
		{[]string{"a)b"}, 0, "reserves"},
		{[]string{"a\tb"}, 0, "reserves"},
		{[]string{"a\u0085b"}, 0, "reserves"},
	} {
		_, err := NewLabel(tc.segments...)
		var le *LabelError
		if !errors.As(err, &le) {
			t.Errorf("NewLabel(%q) = %v, want a LabelError", tc.segments, err)
			continue
		}
		if le.Index != tc.index || !strings.Contains(le.Reason, tc.reason) {
			t.Errorf("NewLabel(%q) = %v, want segment %d %q", tc.segments, err, tc.index, tc.reason)
		}
	}
	for _, text := range []string{"", "/", "users/", "/age", "users//age"} {
		if _, err := ParseLabel(text); err == nil {
			t.Errorf("ParseLabel(%q) succeeded; want a refusal", text)
		}
	}
}

// The segment rule is one rule in two languages. Rust's
// plain_text_and_label_segments_are_one_rule reads the same fixture, so a
// change to either implementation that the other does not follow fails here
// or there.
func TestLabelSegmentRuleMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "label_segments.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Plain    []string `json:"plain"`
		NotPlain []string `json:"not_plain"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Plain) == 0 || len(fixture.NotPlain) == 0 {
		t.Fatalf("fixture is empty: %+v", fixture)
	}
	for _, ok := range fixture.Plain {
		if _, err := NewLabel(ok); err != nil {
			t.Errorf("NewLabel(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range fixture.NotPlain {
		if _, err := NewLabel(bad); err == nil {
			t.Errorf("NewLabel(%q) succeeded; want a refusal", bad)
		}
	}
}

// label is ParseLabel for a label the test knows to be valid: the fixture
// form of the error-returning constructor, since there is no panicking one.
func label(t testing.TB, s string) Label {
	t.Helper()
	l, err := ParseLabel(s)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A struct tag names a field's label, and only a label: the one-part
// context= form, which the guest's lowering cannot seal a field under, is
// refused with the tag to use instead, and a plan built by hand needs a
// non-zero Context.
func TestTagsSpellALabel(t *testing.T) {
	type tagged struct {
		Email string `stash:"label=users/email"`
	}
	p, err := PlanFromTags(reflect.TypeOf(tagged{}))
	if err != nil {
		t.Fatal(err)
	}
	fields := p.Fields()
	if got := fields[0].Context.value(); !reflect.DeepEqual(got, []any{"users", "email"}) {
		t.Errorf("label=users/email bound %#v", got)
	}
	// context= is one part, and a planned field binds a label.
	_, err = PlanFromTags(reflect.TypeOf(struct {
		Notes string `stash:"context=notes/v1"`
	}{}))
	if err == nil || !strings.Contains(err.Error(), `context="notes/v1" names one text part`) || !strings.Contains(err.Error(), "use label=") {
		t.Errorf("context=notes/v1: err = %v; want the one part refused and label= named", err)
	}
	// A one-segment label is one part too.
	_, err = PlanFromTags(reflect.TypeOf(struct {
		Notes string `stash:"label=notes"`
	}{}))
	if err == nil || !strings.Contains(err.Error(), "one part, not a label") {
		t.Errorf("label=notes: err = %v; want the one segment refused", err)
	}
	for name, typ := range map[string]reflect.Type{
		"both": reflect.TypeOf(struct {
			A string `stash:"label=t/a,context=a"`
		}{}),
		"label twice": reflect.TypeOf(struct {
			A string `stash:"label=t/a,label=t/b"`
		}{}),
		"bad label": reflect.TypeOf(struct {
			A string `stash:"label=t/a/"`
		}{}),
		"empty context": reflect.TypeOf(struct {
			A string `stash:"context="`
		}{}),
		"no context": reflect.TypeOf(struct {
			A string `stash:"index=eq"`
		}{}),
	} {
		if _, err := PlanFromTags(typ); err == nil {
			t.Errorf("%s: PlanFromTags succeeded; want a refusal", name)
		}
	}
	if _, err := NewPlan(FieldPlan{Field: "A"}); err == nil || !strings.Contains(err.Error(), "needs a context") {
		t.Errorf("NewPlan without a context = %v", err)
	}
}

// A repeated option is reported as what the author wrote, not as a mix of
// the two keys.
func TestARepeatedOwnContextOptionNamesItself(t *testing.T) {
	_, err := PlanFromTags(reflect.TypeOf(struct {
		A string `stash:"context=a,context=b"`
	}{}))
	if err == nil || !strings.Contains(err.Error(), "context= and context= both given") {
		t.Errorf("err = %v, want the repeated option named", err)
	}
}

// A Label owns its segments, as a Context owns its parts: NewLabel copies
// the slice in and Segments copies it out, so neither side can change the
// name the data is keyed under through a shared array.
func TestLabelOwnsItsSegments(t *testing.T) {
	segments := []string{"users", "email"}
	l, err := NewLabel(segments...)
	if err != nil {
		t.Fatal(err)
	}
	segments[1] = "phone"
	if l.String() != "users/email" {
		t.Errorf("label followed the caller's slice: %s", l)
	}
	out := l.Segments()
	out[0] = "accounts"
	if l.String() != "users/email" {
		t.Errorf("label followed the returned slice: %s", l)
	}
}

// Equal is the supported comparison: == on two list contexts panics.
func TestContextEqualComparesParts(t *testing.T) {
	pair := label(t, "users/email").Context()
	if !pair.Equal(label(t, "users/email").Context()) {
		t.Error("equal labels compare unequal")
	}
	if pair.Equal(label(t, "users/phone").Context()) || pair.Equal(MustContext("users/email")) {
		t.Error("different contexts compare equal")
	}
	if !MustContext("users").Equal(label(t, "users").Context()) {
		t.Error("a one-segment label is not the bare part")
	}
	if (Context{}).Equal(pair) || !(Context{}).Equal(Context{}) {
		t.Error("the zero Context compares wrongly")
	}
	defer func() {
		if recover() == nil {
			t.Error("== on list contexts did not panic; Equal's reason to exist is gone, revisit its doc")
		}
	}()
	_ = pair == label(t, "users/email").Context()
}
