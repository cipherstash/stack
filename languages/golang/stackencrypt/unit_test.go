package stackencrypt

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Pure Go: no guest needed.

func TestKeysetIDRoundTripsCanonicalForm(t *testing.T) {
	const s = "6a70bd18-99ac-4650-b104-37eec3a15b09"
	id, err := ParseKeysetID(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := id.String(); got != s {
		t.Fatalf("String() = %q, want %q", got, s)
	}
	for _, bad := range []string{"", "6a70bd18", "6a70bd18-99ac-4650-b104-37eec3a15b0g", "6a70bd1899ac4650b10437eec3a15b09"} {
		if _, err := ParseKeysetID(bad); err == nil {
			t.Errorf("ParseKeysetID(%q) accepted", bad)
		}
	}
}

func TestSelectorsSpellEveryVariant(t *testing.T) {
	id := KeysetID{1, 2, 3}
	cases := []struct {
		sel  KeysetSelector
		want map[string]any
	}{
		{DefaultKeyset, map[string]any{"default": map[string]any{}}},
		{KeysetName("acme"), map[string]any{"name": "acme"}},
		{id, map[string]any{"id": id[:]}},
		{anyKeyset{}, map[string]any{"any": map[string]any{}}},
	}
	for _, tc := range cases {
		if got := tc.sel.selector(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%T: got %v, want %v", tc.sel, got, tc.want)
		}
		if _, err := vcffi.Marshal(options(tc.sel)); err != nil {
			t.Errorf("%T options do not marshal: %v", tc.sel, err)
		}
	}
}

func TestContextNestsToTheLeft(t *testing.T) {
	c := MustContext("users/age")
	if got := c.value(); got != "users/age" {
		t.Fatalf("bare part = %v", got)
	}
	c, err := c.With(uint64(7))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.With("eu")
	if err != nil {
		t.Fatal(err)
	}
	want := []any{[]any{"users/age", uint64(7)}, "eu"}
	if got := c.value(); !reflect.DeepEqual(got, want) {
		t.Fatalf("With chain = %v, want %v", got, want)
	}
	for _, bad := range []any{1.5, true, nil, []any{"x"}, map[string]any{}} {
		if _, err := NewContext(bad); err == nil {
			t.Errorf("NewContext(%T) accepted", bad)
		}
	}
	if _, err := (Context{}).With("x"); err == nil {
		t.Error("an empty context extended")
	}
}

type taggedUser struct {
	ID     int64  `stash:"-"`
	Age    uint32 `stash:"context=users/age,index=eq;ore"`
	Email  string `stash:"context=users/email,index=eq;match,name=email"`
	Notes  string `stash:"context=users/notes"`
	Plain  string `stash:"plain"`
	NoTag  string
	hidden string `stash:"context=x"` //nolint:unused // proves unexported fields are skipped
}

func TestPlanFromTags(t *testing.T) {
	plan, err := planFor(reflect.TypeOf(taggedUser{}))
	if err != nil {
		t.Fatal(err)
	}
	want := []fieldPlan{
		{index: 1, name: "Age", context: "users/age", outputs: []string{"c", "eq", "ore"}},
		{index: 2, name: "email", context: "users/email", outputs: []string{"c", "eq", "match"}},
		{index: 3, name: "Notes", context: "users/notes", outputs: []string{"c"}},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %+v\nwant %+v", plan, want)
	}

	obj, err := planValue(plan, recordOptions{extension: []any{uint64(7)}})
	if err != nil {
		t.Fatal(err)
	}
	age := obj[0].Value.(vcvalue.Object)
	if got := age[0].Value; !reflect.DeepEqual(got, []any{"users/age", uint64(7)}) {
		t.Fatalf("extended context = %v", got)
	}
	if _, err := vcffi.Marshal(obj); err != nil {
		t.Fatalf("plan does not marshal: %v", err)
	}

	for name, bad := range map[string]any{
		"no context": struct {
			A int `stash:"index=eq"`
		}{},
		"unknown kind": struct {
			A int `stash:"context=c,index=fuzzy"`
		}{},
		"unknown option": struct {
			A int `stash:"context=c,store=true"`
		}{},
		"empty context": struct {
			A int `stash:"context="`
		}{},
		"nothing tagged": struct{ A int }{},
		"not a struct":   42,
		"duplicate name": struct {
			A int `stash:"context=c,name=x"`
			B int `stash:"context=c,name=x"`
		}{},
	} {
		if _, err := planFor(reflect.TypeOf(bad)); err == nil {
			t.Errorf("%s: plan accepted", name)
		}
	}
}

func TestAssignFieldConvertsWithinFamiliesOnly(t *testing.T) {
	type row struct {
		I   int
		U8  uint8
		F   float32
		S   string
		B   []byte
		P   *int64
		Bad bool
	}
	var r row
	rv := reflect.ValueOf(&r).Elem()
	must := func(field string, v any) {
		t.Helper()
		if err := assignField(rv.FieldByName(field), v); err != nil {
			t.Fatalf("%s <- %T: %v", field, v, err)
		}
	}
	must("I", int64(-5))
	must("U8", uint32(200))
	must("F", float32(1.5))
	must("S", "s")
	must("B", []byte{1})
	must("P", int64(9))
	if r.I != -5 || r.U8 != 200 || r.F != 1.5 || r.S != "s" || string(r.B) != "\x01" || *r.P != 9 {
		t.Fatalf("assigned %+v", r)
	}
	for _, bad := range []struct {
		field string
		v     any
	}{
		{"U8", uint32(300)}, // overflow
		{"I", uint64(1)},    // family
		{"S", int64(1)},     // kind
		{"Bad", "true"},     // unsupported target
		{"I", float64(1)},   // family
	} {
		if err := assignField(rv.FieldByName(bad.field), bad.v); !errors.Is(err, errUnassignable) {
			t.Errorf("%s <- %v: got %v, want errUnassignable", bad.field, bad.v, err)
		}
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Type", "application/json")
	h.Add("X-Multi", "a")
	h.Add("X-Multi", "b")
	buf := encodeHeaders(h)
	if string(buf) != "Content-Type: application/json\nX-Multi: a\nX-Multi: b" {
		t.Fatalf("encoded %q", buf)
	}
	back := parseHeaders(append([]byte("garbage line\n"), buf...))
	if got := back.Get("content-type"); got != "application/json" {
		t.Fatalf("parsed content-type %q", got)
	}
	if got := back.Values("X-Multi"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("parsed multi %v", got)
	}
}

func TestTermsAndLeavesScanAndValue(t *testing.T) {
	var eq EqualityTerm
	if err := eq.Scan([]byte{1, 2}); err != nil || !eq.Equal(EqualityTerm{1, 2}) {
		t.Fatalf("scan/equal: %v %v", err, eq)
	}
	if eq.Equal(EqualityTerm{1, 3}) {
		t.Fatal("unequal terms compared equal")
	}
	var m MatchTerm = []byte{1, 0, 2, 0}
	pos, err := m.Positions()
	if err != nil || !reflect.DeepEqual(pos, []uint16{1, 2}) {
		t.Fatalf("positions %v %v", pos, err)
	}
	if _, err := (MatchTerm{1}).Positions(); err == nil {
		t.Fatal("odd match term accepted")
	}
	var s Sealed
	if err := s.Scan(nil); err == nil {
		t.Fatal("NULL scanned into Sealed")
	}
	if err := s.Scan("ab"); err != nil || string(s) != "ab" {
		t.Fatalf("string scan: %v %q", err, s)
	}
	src := []byte{7}
	if err := s.Scan(src); err != nil {
		t.Fatal(err)
	}
	src[0] = 8
	if s[0] != 7 {
		t.Fatal("Scan aliased the driver's slice")
	}
	v, err := s.Value()
	if err != nil || string(v.([]byte)) != "\x07" {
		t.Fatalf("Value: %v %v", v, err)
	}
}

func TestLeafSetKeepsStackEncryptLeavesDistinct(t *testing.T) {
	ct := map[string]any{
		"a": Sealed{1},
		"b": SealedNone{2},
		"c": SealedEmptySeq{3},
		"d": SealedEmptyMap{4},
		"p": vcvalue.Plain{V: "clear"},
	}
	encoded, err := marshalCipherText(ct)
	if err != nil {
		t.Fatal(err)
	}
	back, err := unmarshalCipherText(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, ct) {
		t.Fatalf("round trip %#v", back)
	}
	// A vitaminc leaf is not a stack-encrypt node.
	if _, err := marshalCipherText(map[string]any{"a": vcvalue.Sealed{1}}); err == nil {
		t.Fatal("vcvalue.Sealed accepted as a stack-encrypt leaf")
	}
	if _, err := vcffi.MarshalCipherText(vcffi.VCValueLeaves(), Sealed{1}); err == nil {
		t.Fatal("stackencrypt.Sealed accepted as a vitaminc leaf")
	}
}

func TestStatusMappingIsTotal(t *testing.T) {
	for status, want := range map[uint32]error{
		1: ErrAuthentication, 2: ErrEncoding, 3: ErrState, 4: ErrInternal,
		5: ErrUnauthorized, 6: ErrForbidden, 7: ErrNotFound, 8: ErrConflict,
		9: ErrTransport, 10: ErrKMS, 11: ErrTerm, 12: ErrForeignKeyset,
	} {
		if got := statusError(status); !errors.Is(got, want) {
			t.Errorf("status %d: %v", status, got)
		}
	}
	if got := statusError(99); !errors.Is(got, ErrInternal) {
		t.Errorf("unknown status: %v", got)
	}
}
