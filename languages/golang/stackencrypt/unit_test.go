package stackencrypt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Pure Go: no guest needed.

func TestCommitRecordsPreservesRowsAndIsAtomic(t *testing.T) {
	type row struct {
		ID    int64  `stash:"-"`
		Age   uint8  `stash:"context=users/age"`
		Email string `stash:"context=users/email"`
	}
	plan, err := planFor(reflect.TypeOf(row{}), recordOptions{})
	if err != nil {
		t.Fatal(err)
	}
	decoded := func(age any, email string) vcvalue.Object {
		return vcvalue.Object{{Key: "Age", Value: age}, {Key: "Email", Value: email}}
	}

	// One row per record: unplanned fields survive.
	rows := []row{{ID: 1, Age: 9}, {ID: 2, Age: 9}}
	if err := commitRecords(reflect.ValueOf(&rows).Elem(), []any{decoded(uint32(30), "a"), decoded(uint32(40), "b")}, plan); err != nil {
		t.Fatal(err)
	}
	if want := []row{{1, 30, "a"}, {2, 40, "b"}}; !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}

	// A failing record leaves the slice untouched.
	before := append([]row(nil), rows...)
	err = commitRecords(reflect.ValueOf(&rows).Elem(), []any{decoded(uint32(31), "c"), decoded(uint32(300), "d")}, plan)
	if !errors.Is(err, errUnassignable) {
		t.Fatalf("overflowing batch: %v", err)
	}
	if !reflect.DeepEqual(rows, before) {
		t.Fatalf("partial write: %+v", rows)
	}

	// A different length replaces the slice.
	if err := commitRecords(reflect.ValueOf(&rows).Elem(), []any{decoded(uint32(1), "z")}, plan); err != nil {
		t.Fatal(err)
	}
	if want := []row{{0, 1, "z"}}; !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}

	// One record: same contract on a struct.
	one := row{ID: 7, Age: 1, Email: "keep"}
	if err := commitRecord(reflect.ValueOf(&one).Elem(), decoded(uint32(300), "new"), plan); !errors.Is(err, errUnassignable) {
		t.Fatalf("overflowing record: %v", err)
	}
	if one != (row{7, 1, "keep"}) {
		t.Fatalf("partial write: %+v", one)
	}
	if err := commitRecord(reflect.ValueOf(&one).Elem(), decoded(uint32(2), "new"), plan); err != nil {
		t.Fatal(err)
	}
	if one != (row{7, 2, "new"}) {
		t.Fatalf("record = %+v", one)
	}
}

func TestEncryptRecordRejectsNil(t *testing.T) {
	c := &Client{closed: true}
	cph := c.DefaultKeyset()
	for name, in := range map[string]any{"nil": nil, "nil pointer": (*taggedUser)(nil)} {
		if _, err := cph.EncryptRecord(context.Background(), in); err == nil || errors.Is(err, ErrState) {
			t.Errorf("EncryptRecord(%s): %v, want a record error", name, err)
		}
		if _, err := cph.EncryptRecords(context.Background(), in); err == nil || errors.Is(err, ErrState) {
			t.Errorf("EncryptRecords(%s): %v, want a record error", name, err)
		}
	}
}

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
		{defaultKeyset{}, map[string]any{"default": map[string]any{}}},
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
	plan, err := planFor(reflect.TypeOf(taggedUser{}), recordOptions{})
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
		if _, err := PlanFromTags(reflect.TypeOf(bad)); err == nil {
			t.Errorf("%s: plan accepted", name)
		}
	}
}

// An explicit plan is the tag plan by another route: the same fields give
// the guest the same bytes, and WithPlan's zero value is the tag path.
func TestExplicitPlanIsTheTagPlan(t *testing.T) {
	typ := reflect.TypeOf(taggedUser{})
	explicit, err := NewPlan(
		PlanField{Field: "Age", Context: "users/age", Index: []TermKind{Equality, Ore}},
		PlanField{Field: "Email", Name: "email", Context: "users/email", Index: []TermKind{Equality, Match}},
		PlanField{Field: "Notes", Context: "users/notes"},
	)
	if err != nil {
		t.Fatal(err)
	}
	tagged, err := PlanFromTags(typ)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(explicit.Fields(), tagged.Fields()) {
		t.Fatalf("fields differ:\n%+v\n%+v", explicit.Fields(), tagged.Fields())
	}
	encode := func(p Plan) []byte {
		bound, err := p.bind(typ)
		if err != nil {
			t.Fatal(err)
		}
		obj, err := planValue(bound, recordOptions{extension: []any{uint64(7)}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := vcffi.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if a, b := encode(explicit), encode(tagged); !bytes.Equal(a, b) {
		t.Fatalf("guest input differs:\n%x\n%x", a, b)
	}
	viaOption, err := planFor(typ, applyOptions([]RecordOption{WithPlan(explicit)}))
	if err != nil {
		t.Fatal(err)
	}
	viaTags, err := planFor(typ, applyOptions([]RecordOption{WithPlan(Plan{})}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(viaOption, viaTags) {
		t.Fatalf("bound plans differ:\n%+v\n%+v", viaOption, viaTags)
	}
	// Fields returns a copy.
	explicit.Fields()[0].Context = "changed"
	if explicit.Fields()[0].Context != "users/age" {
		t.Fatal("Fields exposed the plan's own slice")
	}
}

// A plan can name only exported, direct fields of the struct it binds to,
// and only fields that exist; an untagged struct binds fine under it.
func TestPlanBindsByFieldName(t *testing.T) {
	type embedded struct{ Inner string }
	type untagged struct {
		embedded
		Email  string
		hidden string //nolint:unused // proves unexported fields are refused
	}
	typ := reflect.TypeOf(untagged{})
	if _, err := PlanFromTags(typ); err == nil {
		t.Fatal("untagged struct has a tag plan")
	}
	ok, err := NewPlan(PlanField{Field: "Email", Context: "c"})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := planFor(typ, applyOptions([]RecordOption{WithPlan(ok)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(bound) != 1 || bound[0].index != 1 || bound[0].name != "Email" {
		t.Fatalf("bound = %+v", bound)
	}
	for name, field := range map[string]string{
		"missing":    "Nope",
		"unexported": "hidden",
		"promoted":   "Inner",
	} {
		p, err := NewPlan(PlanField{Field: field, Context: "c"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.bind(typ); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: bind error = %v, want one naming %q", name, err, field)
		}
	}
	if _, err := ok.bind(reflect.TypeOf(42)); err == nil {
		t.Error("bound to a non-struct")
	}
}

func TestNewPlanValidates(t *testing.T) {
	for name, fields := range map[string][]PlanField{
		"no fields":      nil,
		"no field name":  {{Context: "c"}},
		"no context":     {{Field: "A"}},
		"unknown kind":   {{Field: "A", Context: "c", Index: []TermKind{TermKind(9)}}},
		"duplicate name": {{Field: "A", Context: "c", Name: "x"}, {Field: "B", Context: "c", Name: "x"}},
		"field twice":    {{Field: "A", Context: "c"}, {Field: "A", Context: "d"}},
	} {
		if _, err := NewPlan(fields...); err == nil {
			t.Errorf("%s: plan accepted", name)
		}
	}
	if (Plan{}).Fields() != nil {
		t.Error("zero plan has fields")
	}
}

func TestAssignFieldConvertsWithinFamiliesOnly(t *testing.T) {
	type flag bool
	type name string
	type raw []byte
	type row struct {
		I    int
		U8   uint8
		F    float32
		F64  float64
		S    string
		B    []byte
		P    *int64
		Bool bool
		Flag flag
		Name name
		Raw  raw
		M    map[string]int
		Any  any
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
	must("F", float64(0.5)) // exactly representable: narrows
	must("F64", float32(0.1))
	must("S", "s")
	must("B", []byte{1})
	must("P", int64(9))
	must("Bool", true)
	must("Flag", true)
	must("Name", "n")
	must("Raw", []byte{2})
	if r.I != -5 || r.U8 != 200 || r.F != 0.5 || r.F64 != float64(float32(0.1)) || r.S != "s" || string(r.B) != "\x01" || *r.P != 9 ||
		!r.Bool || !bool(r.Flag) || r.Name != "n" || string(r.Raw) != "\x02" {
		t.Fatalf("assigned %+v", r)
	}
	// A sealed none decodes as nil: only a field that can hold one takes it.
	r.P, r.B, r.M, r.Any = new(int64), []byte{1}, map[string]int{"a": 1}, 1
	must("P", nil)
	must("B", nil)
	must("M", nil)
	must("Any", nil)
	if r.P != nil || r.B != nil || r.M != nil || r.Any != nil {
		t.Fatalf("nil did not clear: %+v", r)
	}
	for _, bad := range []struct {
		field string
		v     any
	}{
		{"U8", uint32(300)},      // overflow
		{"I", uint64(1)},         // family
		{"S", int64(1)},          // kind
		{"Bool", "true"},         // kind
		{"I", float64(1)},        // family
		{"F", float64(0.1)},      // not representable as float32
		{"F", float64(16777217)}, // in range, not representable
		{"I", nil},               // a none into a scalar
		{"S", nil},               // a none into a scalar
		{"Bool", nil},            // a none into a scalar
		{"Name", []byte("n")},    // kind
		{"Raw", "r"},             // kind
	} {
		if err := assignField(rv.FieldByName(bad.field), bad.v); !errors.Is(err, errUnassignable) {
			t.Errorf("%s <- %v: got %v, want errUnassignable", bad.field, bad.v, err)
		}
	}
}

// The request body wipes its buffer when closed, not before: reads up to
// Close see the bytes, Close zeroes them, a read after Close is an error
// rather than zeros, and a second Close is harmless.
func TestRequestBodyWipesOnClose(t *testing.T) {
	src := []byte(`{"client_id":"abc"}`)
	b := newRequestBody(src)
	wipe(src) // the guest wipes its own buffer on return; the copy must not notice
	got, err := io.ReadAll(b)
	if err != nil || string(got) != `{"client_id":"abc"}` {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(b.buf, make([]byte, len(b.buf))) {
		t.Errorf("buffer after Close = %q, want zeros", b.buf)
	}
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, errRequestBodyClosed) {
		t.Errorf("Read after Close: %v, want errRequestBodyClosed", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A close before the send is complete fails the send rather than
	// letting zeros through as the request.
	b = newRequestBody([]byte("0123456789"))
	if n, err := b.Read(make([]byte, 4)); n != 4 || err != nil {
		t.Fatalf("partial Read = %d, %v", n, err)
	}
	_ = b.Close()
	if _, err := io.ReadAll(b); !errors.Is(err, errRequestBodyClosed) {
		t.Errorf("ReadAll after an early Close: %v, want errRequestBodyClosed", err)
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

// The Go ordering of ORE and OPE terms agrees with Rust's Ord: testdata
// holds ciphertexts the cllw-ore crate produced, each group in ascending
// plaintext order, and every pair must order the same way here.
func TestTermOrderingAgreesWithRust(t *testing.T) {
	f, err := os.Open("testdata/cllw_order.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	groups := map[string][][]byte{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		kind, typ, raw := parts[0], parts[1], parts[len(parts)-1]
		if raw == "-" {
			raw = ""
		}
		term, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		key := kind + " " + typ
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], term)
	}
	if len(order) != 4 {
		t.Fatalf("expected 4 vector groups, found %v", order)
	}
	for _, key := range order {
		terms := groups[key]
		compare := func(i, j int) int {
			if strings.HasPrefix(key, "ope") {
				return OpeTerm(terms[i]).Compare(OpeTerm(terms[j]))
			}
			return OreTerm(terms[i]).Compare(OreTerm(terms[j]))
		}
		for i := range terms {
			for j := range terms {
				want := 0
				if i < j {
					want = -1
				} else if i > j {
					want = 1
				}
				if got := compare(i, j); got != want {
					t.Errorf("%s: compare(%d, %d) = %d, want %d", key, i, j, got, want)
				}
			}
		}
		if strings.HasPrefix(key, "ore") && !OreTerm(terms[0]).Less(OreTerm(terms[1])) {
			t.Errorf("%s: Less disagrees with Compare", key)
		}
	}
	// A different length that shares no prefix bytes still orders by the
	// first difference, and an empty term is less than any other.
	if OreTerm(nil).Compare(OreTerm{1}) != -1 || (OreTerm{1}).Compare(OreTerm(nil)) != 1 || OreTerm(nil).Compare(OreTerm(nil)) != 0 {
		t.Error("empty ORE terms do not order by length")
	}
}
