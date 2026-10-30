package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"golang.org/x/tools/go/packages"
)

// The element match of a document field (element_match): the generated
// Elements.<Array>.Match on testusers.Entity's custom field values, whose
// contacts order relationship, previous_call_count and age.

const emergencyContacts = "$.extra.emergency_contacts[*]"

// elementsOperand is eql_v4.query_json_elements as the engine writes it:
// per predicate, the tokens of a read of the member's full path and its
// bounds, each a leaf operand.
type elementsOperand struct {
	M []map[string]json.RawMessage `json:"m"`
}

func decodeElements(t *testing.T, q []byte) elementsOperand {
	t.Helper()
	var op elementsOperand
	dec := json.NewDecoder(bytes.NewReader(q))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&op); err != nil {
		t.Fatalf("the operand is not {\"m\": [...]}: %v", err)
	}
	return op
}

// keys are a member's keys, sorted.
func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func tokensOf(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var tokens []string
	if err := json.Unmarshal(raw, &tokens); err != nil {
		t.Fatal(err)
	}
	return tokens
}

// The operand Match derives is built of what the other operators derive on
// the same field: each member's tokens are a subtree read of its full path
// at the bound, the probe last, and its bounds are the leaf operands the
// orderings at that path derive, equality both inclusive bounds at one
// value.
func TestElementMatchIsTheReadsAndTheOrderingsOfEachMember(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.EntityFields.CustomFieldValues
	contact := testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts
	opts := encrypt.JSONReadOptions{WildcardBound: 4}
	q, err := f.Elements.ExtraEmergencyContacts.Match(ctx, cipher, opts,
		encrypt.AtPath(contact.Relationship).Eq("Sibling"),
		encrypt.AtPath(contact.PreviousCallCount).Gt(5),
		encrypt.AtPath(contact.Age).Between(18, 40),
	)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := q.Value(); err != nil || !strings.HasPrefix(fmt.Sprint(v), `{"m":`) {
		t.Fatalf("Match binds as its JSON: %v %v", v, err)
	}
	op := decodeElements(t, q)
	if len(op.M) != 3 {
		t.Fatalf("%d members, want one per predicate", len(op.M))
	}
	for i, want := range [][]string{{"gte", "lte", "t"}, {"gt", "t"}, {"gte", "lte", "t"}} {
		if got := keys(op.M[i]); !slices.Equal(got, want) {
			t.Errorf("member %d has %v, want %v", i, got, want)
		}
	}
	// Each member's tokens are the subtree read of its full path at the
	// same bound: bound elements, then the probe.
	for i, member := range []string{"relationship", "previous_call_count", "age"} {
		read, err := f.Subtree(ctx, cipher, emergencyContacts+"."+member, opts)
		if err != nil {
			t.Fatal(err)
		}
		tokens := tokensOf(t, op.M[i]["t"])
		if len(tokens) != int(opts.WildcardBound)+1 || !slices.Equal(tokens, []string(read.Tokens())) {
			t.Errorf("%s: %d tokens, not the subtree read's %d", member, len(tokens), len(read.Tokens()))
		}
	}
	// The bounds are the orderings' leaf operands at the member's path.
	leaf := func(q []byte, err error) json.RawMessage {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	sameLeaf := func(name string, got, want json.RawMessage) {
		t.Helper()
		if !sameJSON(t, got, want) {
			t.Errorf("%s: %s, want the ordering's %s", name, got, want)
		}
	}
	eq := op.M[0]
	sameLeaf("eq gte", eq["gte"], leaf(f.At.ExtraEmergencyContactsRelationship.Gte(ctx, cipher, "Sibling")))
	sameLeaf("eq lte", eq["lte"], eq["gte"])
	sameLeaf("gt", op.M[1]["gt"], leaf(f.At.ExtraEmergencyContactsPreviousCallCount.Gt(ctx, cipher, 5)))
	rng, err := f.At.ExtraEmergencyContactsAge.Between(ctx, cipher, 18, 40)
	if err != nil {
		t.Fatal(err)
	}
	sameLeaf("between low", op.M[2]["gte"], json.RawMessage(rng.Low))
	sameLeaf("between high", op.M[2]["lte"], json.RawMessage(rng.High))
	// A member named at run time derives the operand its path does, and
	// so does a value given as its JSON text.
	contacts := f.Elements.ExtraEmergencyContacts
	named, err := contacts.Match(ctx, cipher, opts,
		contacts.Member("relationship").Eq("Sibling"),
		contacts.Member("previous_call_count").Gt(5),
		contacts.Member("age").Between(18, int64(40)),
	)
	if err != nil || !sameJSON(t, named, q) {
		t.Fatalf("a member named at run time derives another operand: %v", err)
	}
	raw, err := contacts.Match(ctx, cipher, opts,
		contacts.Member("relationship").Eq(json.RawMessage(`"Sibling"`)),
		contacts.Member("previous_call_count").Gt(json.RawMessage(`5`)),
		contacts.Member("age").Between(json.RawMessage(`18`), json.RawMessage(`40`)),
	)
	if err != nil || !sameJSON(t, raw, q) {
		t.Fatalf("JSON text derives another operand: %v", err)
	}
	// The other comparisons, one bound each; the default bound is 64.
	for _, c := range []struct {
		p   encrypt.ElementPredicate[testusers.EntityCustomFieldValuesFieldElementsExtraEmergencyContacts]
		key string
	}{
		{encrypt.AtPath(contact.Age).Lt(30), "lt"},
		{encrypt.AtPath(contact.Age).Lte(30), "lte"},
		{encrypt.AtPath(contact.Age).Gte(30), "gte"},
	} {
		q, err := contacts.Match(ctx, cipher, encrypt.JSONReadOptions{}, c.p)
		if err != nil {
			t.Fatal(err)
		}
		m := decodeElements(t, q).M[0]
		if got := keys(m); !slices.Equal(got, []string{c.key, "t"}) {
			t.Errorf("%s: %v", c.key, got)
		}
		if n := len(tokensOf(t, m["t"])); n != 65 {
			t.Errorf("%s: %d tokens at the default bound, want 65", c.key, n)
		}
	}
	// A field whose arrays order no member has no Elements.
	if _, ok := reflect.TypeOf(testusers.SubscriberFields.Prefs).FieldByName("Elements"); ok {
		t.Fatal("Prefs orders no member, and has Elements")
	}
}

// What Match refuses before it asks the engine: each is the sentinel the
// engine's refusal would be, with no Diagnostic, since the guest was never
// called. An unordered member is named with the array and the members the
// field orders there.
func TestElementMatchRefusesBeforeTheEngine(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	contacts := testusers.EntityFields.CustomFieldValues.Elements.ExtraEmergencyContacts
	member := contacts.Member
	type predicate = encrypt.ElementPredicate[testusers.EntityCustomFieldValuesFieldElementsExtraEmergencyContacts]
	var zeroPath encrypt.Path[testusers.EntityCustomFieldValuesFieldElementsExtraEmergencyContacts, int64]
	for _, tc := range []struct {
		name       string
		predicates []predicate
		kind       error
		says       []string
	}{
		{"no predicates", nil, encrypt.ErrEncoding, []string{"at least one predicate", emergencyContacts}},
		{"a zero predicate", []predicate{{}}, encrypt.ErrEncoding, []string{"zero ElementPredicate", "encrypt.AtPath", "Member"}},
		{"a zero path", []predicate{encrypt.AtPath(zeroPath).Eq(1)}, encrypt.ErrEncoding, []string{"names no member", "zero encrypt.Path", "relationship, previous_call_count, age"}},
		{"a wildcard in a member", []predicate{member("calls[*].at").Eq(1)}, encrypt.ErrEncoding, []string{`"calls[*].at"`, "has a wildcard", emergencyContacts}},
		{"an unordered member", []predicate{member("relationship").Eq("secret value"), member("name").Eq("secret value")}, encrypt.ErrTerm, []string{`"name"`, "is not ordered", emergencyContacts, "relationship, previous_call_count, age"}},
		{"a member spelled another way", []predicate{member(`["age"]`).Gt(5)}, encrypt.ErrTerm, []string{`"[\"age\"]"`, "is not ordered"}},
		{"a []byte value", []predicate{member("relationship").Eq([]byte(`"Sibling"`))}, encrypt.ErrEncoding, []string{"base64"}},
	} {
		_, err := contacts.Match(ctx, cipher, encrypt.JSONReadOptions{}, tc.predicates...)
		var d *encrypt.Diagnostic
		if !errors.Is(err, tc.kind) || errors.As(err, &d) {
			t.Errorf("%s: %v, want %v from the SDK", tc.name, err, tc.kind)
			continue
		}
		for _, want := range tc.says {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q does not say %q", tc.name, err, want)
			}
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "Sibling") {
			t.Errorf("%s: the error holds a value: %v", tc.name, err)
		}
	}
	// No cipher is a returned error, not a panic.
	if _, err := contacts.Match(ctx, nil, encrypt.JSONReadOptions{}, member("age").Eq(3)); err == nil {
		t.Fatal("Match with no cipher")
	}
}

// contactsPlan declares a document whose contacts order relationship,
// previous_call_count and age, for element_match through QueryTerm, which
// sends any input the engine reads.
func contactsPlan() *record.Plan {
	return &record.Plan{Context: []string{"entities"}, Fields: []record.Field{{
		Name: "custom", Kind: record.JSON, Target: "JsonSearch", Null: record.SQLNull,
		TargetOptions: &record.TargetOptions{Ordered: []string{
			emergencyContacts + ".relationship", emergencyContacts + ".previous_call_count", emergencyContacts + ".age",
		}},
	}}}
}

// What the engine refuses of an element_match input, through the guest:
// each is ErrEncoding (the input) or ErrTerm (the index), with the engine's
// reason or code, the field named, and no value in the text.
func TestElementMatchEngineRefusalsAreTypedErrors(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	type obj = vcvalue.Object
	pred := func(member, op string, kv ...vcvalue.Field) obj {
		return append(obj{{Key: "member", Value: member}, {Key: "op", Value: op}}, kv...)
	}
	eq := func(member, v string) obj { return pred(member, "eq", vcvalue.Field{Key: "json", Value: []byte(v)}) }
	input := func(path string, preds ...any) obj {
		return obj{{Key: "path", Value: path}, {Key: "predicates", Value: preds}}
	}
	deep := strings.Repeat("a.", 130) + "a"
	for _, tc := range []struct {
		name   string
		input  obj
		kind   error
		reason string // the data plan's reason
		code   string // or the index's code
	}{
		{"a path with no wildcard", input("$.extra", eq("relationship", `"secret"`)), encrypt.ErrEncoding, "json_path_no_wildcard", ""},
		{"a bound of 0", append(input(emergencyContacts, eq("relationship", `"secret"`)), vcvalue.Field{Key: "wildcard_bound", Value: uint32(0)}), encrypt.ErrEncoding, "json_wildcard_bound_zero", ""},
		{"no predicates", input(emergencyContacts), encrypt.ErrEncoding, "json_no_predicates", ""},
		{"an unknown op", input(emergencyContacts, pred("age", "ne", vcvalue.Field{Key: "json", Value: []byte(`1`)})), encrypt.ErrEncoding, "json_unknown_predicate_op", ""},
		{"keys that do not fit the op", input(emergencyContacts, pred("age", "eq", vcvalue.Field{Key: "low", Value: []byte(`1`)}, vcvalue.Field{Key: "high", Value: []byte(`2`)})), encrypt.ErrEncoding, "json_input", ""},
		{"a wildcard in a member", input(emergencyContacts, eq("calls[*].at", `1`)), encrypt.ErrEncoding, "json_path_wildcard", ""},
		{"a position in the path", input("$.extra.emergency_contacts[*].x[2].y[*]", eq("age", `1`)), encrypt.ErrTerm, "", "stack_encrypt::json_ordering_at_position"},
		{"an unordered member", input(emergencyContacts, eq("name", `"secret"`)), encrypt.ErrTerm, "", "stack_encrypt::json_path_not_ordered"},
		{"a value no ordering takes", input(emergencyContacts, eq("relationship", `true`)), encrypt.ErrTerm, "", "stack_encrypt::json_leaf_not_ordered"},
		{"a member that is not a path", input(emergencyContacts, eq("relationship.", `"secret"`)), encrypt.ErrTerm, "", "stack_encrypt::json_path"},
		{"a member past the document's depth", input(emergencyContacts, eq(deep, `1`)), encrypt.ErrTerm, "", "stack_encrypt::json_too_deep"},
	} {
		_, err := cipher.QueryTerm(ctx, contactsPlan(), "custom", "element_match", tc.input)
		var d *encrypt.Diagnostic
		if !errors.Is(err, tc.kind) || !errors.As(err, &d) {
			t.Errorf("%s: %v, want %v with a Diagnostic", tc.name, err, tc.kind)
			continue
		}
		if tc.reason != "" && (d.Reason() != tc.reason || d.Field() != "custom") {
			t.Errorf("%s: reason %q on %q, want %q: %v", tc.name, d.Reason(), d.Field(), tc.reason, err)
		}
		if tc.code != "" && d.Code != tc.code {
			t.Errorf("%s: code %q, want %q: %v", tc.name, d.Code, tc.code, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the error holds a value: %v", tc.name, err)
		}
	}
	// A member that is not a path is refused at an offset into the
	// member's own text: "relationship." breaks after its 13 bytes.
	_, err := cipher.QueryTerm(ctx, contactsPlan(), "custom", "element_match", input(emergencyContacts, eq("relationship.", `"x"`)))
	var d *encrypt.Diagnostic
	if !errors.As(err, &d) || d.Fields["at"] != uint64(13) {
		t.Errorf("the offset into the member: %+v", d)
	}
}

// visits stands for an array's type, as the generator writes one per array.
type visits struct{}

// A path names its member, and a predicate made at it keeps the member
// relative to the array, with the comparison and its values.
func TestAtPathMakesThePredicatesOfItsMember(t *testing.T) {
	place := encrypt.NewPath[visits, string]("$.visits[*]", "address.city")
	if got := place.String(); got != "$.visits[*].address.city" {
		t.Fatalf("String: %s", got)
	}
	for _, c := range []struct {
		p      encrypt.ElementPredicate[visits]
		op     string
		values []any
	}{
		{encrypt.AtPath(place).Eq("a"), "eq", []any{"a"}},
		{encrypt.AtPath(place).Lt("b"), "lt", []any{"b"}},
		{encrypt.AtPath(place).Lte("c"), "lte", []any{"c"}},
		{encrypt.AtPath(place).Gt("d"), "gt", []any{"d"}},
		{encrypt.AtPath(place).Gte("e"), "gte", []any{"e"}},
		{encrypt.AtPath(place).Between("f", "g"), "between", []any{"f", "g"}},
	} {
		if c.p.Member() != "address.city" || c.p.Op() != c.op || !reflect.DeepEqual(c.p.Values(), c.values) {
			t.Errorf("%s: %q %q %v", c.op, c.p.Member(), c.p.Op(), c.p.Values())
		}
	}
	if (encrypt.ElementPredicate[visits]{}).Op() != "" || (encrypt.Path[visits, int64]{}).String() != "" {
		t.Fatal("a zero predicate has a comparison, or a zero path a member")
	}
}

// A predicate holds plaintext values: it prints and logs its member and
// comparison, never them.
func TestElementPredicatesPrintAndLogWithoutTheirValues(t *testing.T) {
	contact := testusers.EntityPaths.CustomFieldValues.Extra.EmergencyContacts
	predicates := []encrypt.ElementPredicate[testusers.EntityCustomFieldValuesFieldElementsExtraEmergencyContacts]{
		encrypt.AtPath(contact.Relationship).Eq("Sibling"),
		encrypt.AtPath(contact.Age).Between(1234567, 7654321),
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("predicates", "p", predicates[0], "q", predicates[1])
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		out := fmt.Sprintf(verb, predicates)
		for _, hidden := range []string{"Sibling", "1234567", "7654321"} {
			if strings.Contains(out, hidden) || strings.Contains(logged.String(), hidden) {
				t.Errorf("%s shows %q: %s %s", verb, hidden, out, logged.String())
			}
		}
		if !strings.Contains(out, "relationship") || !strings.Contains(out, "between") {
			t.Errorf("%s names no member or comparison: %s", verb, out)
		}
	}
	if p := predicates[1]; p.Member() != "age" || p.Op() != "between" || !reflect.DeepEqual(p.Values(), []any{int64(1234567), int64(7654321)}) {
		t.Fatalf("accessors: %q %q %v", p.Member(), p.Op(), p.Values())
	}
	// Values is a copy: changing it leaves the predicate as built.
	predicates[1].Values()[0] = 0
	if got := predicates[1].Values(); !reflect.DeepEqual(got, []any{int64(1234567), int64(7654321)}) {
		t.Fatalf("a predicate changed through Values: %v", got)
	}
	if s := (encrypt.ElementPredicate[visits]{}).String(); s != "encrypt.ElementPredicate{}" {
		t.Fatalf("a zero predicate prints %s", s)
	}
}

// A predicate holds its own copy of a json.RawMessage or []byte value:
// changing the caller's bytes after the predicate is made, or the bytes
// Values returns, leaves the predicate as built.
func TestElementPredicatesCopyTheirByteValues(t *testing.T) {
	raw := json.RawMessage(`"Sibling"`)
	low, high := []byte("10"), []byte("20")
	relationship := encrypt.AtPath(encrypt.NewPath[visits, json.RawMessage]("$.visits[*]", "relationship"))
	age := encrypt.AtPath(encrypt.NewPath[visits, any]("$.visits[*]", "age"))
	predicates := []encrypt.ElementPredicate[visits]{
		relationship.Eq(raw),
		relationship.Lt(raw),
		relationship.Lte(raw),
		relationship.Gt(raw),
		relationship.Gte(raw),
		age.Between(low, high),
	}
	want := make([][]any, len(predicates))
	for i, p := range predicates {
		want[i] = p.Values()
	}
	copy(raw, `"XXXXXXX"`)
	copy(low, "99")
	copy(high, "99")
	for i, p := range predicates {
		if got := p.Values(); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("%s changed with the caller's bytes: %s", p.Op(), got)
		}
		for _, v := range p.Values() {
			switch b := v.(type) {
			case json.RawMessage:
				b[0] = 'X'
			case []byte:
				b[0] = 'X'
			default:
				t.Fatalf("%s holds a %T, not the type it was given", p.Op(), v)
			}
		}
		if got := p.Values(); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("%s changed through the bytes Values returned: %s", p.Op(), got)
		}
	}
	if got := predicates[0].Values()[0]; !reflect.DeepEqual(got, json.RawMessage(`"Sibling"`)) {
		t.Errorf("Eq holds %s", got)
	}
	if got := predicates[5].Values(); !reflect.DeepEqual(got, []any{[]byte("10"), []byte("20")}) {
		t.Errorf("Between holds %s", got)
	}
}

// The compiler refuses a predicate whose value is not the member's Go
// type, and one on a member of another array, as the generated code types
// them. Checked by loading testusers with a probe file beside it.
func TestElementMatchTypeChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks a package")
	}
	dir, err := filepath.Abs(filepath.Join("internal", "testusers"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(body string) []string {
		t.Helper()
		src := "package testusers\n\nimport (\n\t\"context\"\n\n\t\"github.com/cipherstash/stack/languages/golang/encrypt\"\n)\n\nfunc probe(ctx context.Context, c *encrypt.Cipher) {\n\tcontacts := EntityFields.CustomFieldValues.Elements.ExtraEmergencyContacts\n\tcontact := EntityPaths.CustomFieldValues.Extra.EmergencyContacts\n\t_, _ = contacts, contact\n" + body + "}\n"
		cfg := &packages.Config{Context: context.Background(), Dir: dir, Mode: packages.NeedName | packages.NeedTypes, Overlay: map[string][]byte{filepath.Join(dir, "zz_probe.go"): []byte(src)}}
		pkgs, err := packages.Load(cfg, ".")
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("load: %v", err)
		}
		var errs []string
		for _, e := range pkgs[0].Errors {
			errs = append(errs, e.Msg)
		}
		return errs
	}
	if errs := check("\t_, _ = contacts.Match(ctx, c, encrypt.JSONReadOptions{}, encrypt.AtPath(contact.Relationship).Eq(\"Sibling\"), encrypt.AtPath(contact.Age).Gt(15), contacts.Member(\"age\").Gt(\"15\"))\n"); len(errs) != 0 {
		t.Fatalf("the element match as a program writes it does not compile: %v", errs)
	}
	for _, c := range []struct{ name, body, want string }{
		{"a value of another type", "\t_, _ = contacts.Match(ctx, c, encrypt.JSONReadOptions{}, encrypt.AtPath(contact.Age).Gt(\"15\"))\n", `cannot use "15" (untyped string constant) as int64 value`},
		{"a member of another array", "\t_, _ = contacts.Match(ctx, c, encrypt.JSONReadOptions{}, encrypt.AtPath(SubscriberPaths.Profile.Visits.At).Gt(15))\n", "encrypt.ElementPredicate[SubscriberProfileFieldElementsVisits]) as encrypt.ElementPredicate[EntityCustomFieldValuesFieldElementsExtraEmergencyContacts] value"},
	} {
		// The loader reports the one mistake from go list and from the
		// type checker: every error must be it.
		errs := check(c.body)
		if len(errs) == 0 {
			t.Errorf("%s: compiles", c.name)
		}
		for _, e := range errs {
			if !strings.Contains(e, c.want) {
				t.Errorf("%s: %s, want only %q", c.name, e, c.want)
			}
		}
	}
}
