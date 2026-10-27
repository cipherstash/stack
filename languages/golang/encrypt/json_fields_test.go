package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Generated code for json.RawMessage fields stored as JsonSearch:
// testusers.Customer's Profile, ordered at $.age and $.visits[*].at, and its
// optional Prefs.

func rawPtr(s string) *json.RawMessage {
	r := json.RawMessage(s)
	return &r
}

// sameJSON reports whether two JSON texts hold the same value: the
// document is sealed as values, so its text is not promised back byte for
// byte.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return reflect.DeepEqual(x, y)
}

func TestACustomersDocumentsRoundTrip(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	in := []testusers.Customer{
		{ID: 1, Profile: json.RawMessage(`{"name":"Alice","age":34,"visits":[{"at":3},{"at":1}]}`), Prefs: rawPtr(`{"theme":"dark"}`)},
		{ID: 2, Profile: json.RawMessage(`[1,2,3]`)},
		{ID: 3, Profile: json.RawMessage(`null`), Prefs: rawPtr(`null`)},
	}
	encrypted, err := testusers.EncryptCustomer(ctx, c.DefaultKeyset(), in)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted[1].Prefs != nil || encrypted[2].Prefs == nil {
		t.Fatalf("a nil document is SQL NULL, a JSON null is a document: %v %v", encrypted[1].Prefs, encrypted[2].Prefs)
	}
	if s := encrypted[0].String(); strings.Contains(s, "Alice") {
		t.Fatalf("String shows the document: %s", s)
	}
	back, err := testusers.DecryptCustomer(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range in {
		if back[i].ID != in[i].ID || !sameJSON(t, back[i].Profile, in[i].Profile) {
			t.Fatalf("row %d: %s", i, back[i].Profile)
		}
		if (back[i].Prefs == nil) != (in[i].Prefs == nil) || (in[i].Prefs != nil && !sameJSON(t, *back[i].Prefs, *in[i].Prefs)) {
			t.Fatalf("row %d prefs: %v", i, back[i].Prefs)
		}
	}
	// Empty bytes are not a document: a required field takes JSON.
	if _, err := testusers.EncryptCustomer(ctx, c.DefaultKeyset(), []testusers.Customer{{ID: 4}}); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("an empty document: %v", err)
	}
}

func TestACustomersFieldsDeriveEachQuery(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.CustomerFields.Profile
	contains, err := f.Contains(ctx, cipher, json.RawMessage(`{"name":"Alice"}`))
	if err != nil || len(contains) == 0 {
		t.Fatalf("Contains: %v", err)
	}
	if v, err := contains.Value(); err != nil || !strings.Contains(fmt.Sprint(v), `"sv"`) {
		t.Fatalf("Contains binds as JSON: %v %v", v, err)
	}
	if _, err := f.ContainedBy(ctx, cipher, json.RawMessage(`{"name":"Alice","age":34}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.EqAt(ctx, cipher, "$.name", json.RawMessage(`"Alice"`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.At.Age.Lt(ctx, cipher, json.RawMessage(`40`)); err != nil {
		t.Fatal(err)
	}
	rng, err := f.At.VisitsAt.Between(ctx, cipher, json.RawMessage(`1`), json.RawMessage(`2`))
	if err != nil || len(rng.Low) == 0 || len(rng.High) == 0 {
		t.Fatalf("Between: %+v %v", rng, err)
	}
	sel, err := f.Selector(ctx, cipher, "$.name")
	if err != nil || sel.Selector() == "" {
		t.Fatalf("Selector: %v", err)
	}
	read, err := f.Subtree(ctx, cipher, "$.visits[*]", encrypt.JSONReadOptions{WildcardBound: 2})
	if err != nil || len(read.Tokens()) != 3 {
		t.Fatalf("Subtree: %v %v", read.Tokens(), err)
	}
	if v, err := read.Tokens().Value(); err != nil || !strings.HasPrefix(fmt.Sprint(v), `{"`) {
		t.Fatalf("Tokens bind as a text[] literal: %v %v", v, err)
	}
	if _, err := f.Children(ctx, cipher, "$.visits"); err != nil {
		t.Fatal(err)
	}
	// An ordered path's own selector is the field's at that path.
	pathSel, err := f.At.VisitsAt.Selector(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if fieldSel, _ := f.Selector(ctx, cipher, "$.visits[*].at"); pathSel.Selector() != fieldSel.Selector() {
		t.Fatal("the accessor's selector is another path's")
	}
	// OpenOne refuses a wildcard read before anything is opened, whatever
	// the rows hold, and its error does not name the path, which can hold
	// a customer's key. A quoted key that spells [*] names one member: the
	// engine derives one token for it, and OpenOne takes it. A zero
	// selector, token or tokens binds nothing.
	if _, err := read.OpenOne(ctx, nil); !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "visits") {
		t.Fatalf("OpenOne on a wildcard read: %v", err)
	}
	quoted, err := f.Subtree(ctx, cipher, `$["a[*]"]`, encrypt.JSONReadOptions{})
	if err != nil || len(quoted.Tokens()) != 1 {
		t.Fatalf("Subtree at a quoted key: %v %v", quoted.Tokens(), err)
	}
	if v, err := quoted.OpenOne(ctx, nil); err != nil || v.Found {
		t.Fatalf("OpenOne at a quoted key that spells [*]: %+v %v", v, err)
	}
	if _, err := (encrypt.JSONSelector("")).Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a zero selector binds: %v", err)
	}
	if _, err := (encrypt.JSONToken("")).Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a zero token binds: %v", err)
	}
	if _, err := (encrypt.JSONTokens(nil)).Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("no tokens bind: %v", err)
	}
	if _, err := (encrypt.JSONRead[eql.JSONEntry]{}).Tokens().Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a zero read's tokens bind: %v", err)
	}
	// A selection over rows with no entry opens to no value without a
	// request.
	none, err := sel.Open(ctx, make([]*eql.JSONEntry, 3))
	if err != nil || len(none) != 3 || none[0].Found || none[2].Found {
		t.Fatalf("an empty page: %+v %v", none, err)
	}
	// What the engine refuses: an ordering on a value no ordering takes, a
	// container at a path, a position in a selector, a wildcard where one
	// node is named. Each is a returned error naming no value.
	for name, err := range map[string]error{
		"bool ordering": func() error { _, err := f.At.Age.Gt(ctx, cipher, json.RawMessage(`true`)); return err }(),
		"container eq":  func() error { _, err := f.EqAt(ctx, cipher, "$.name", json.RawMessage(`{"secret":1}`)); return err }(),
		"position":      func() error { _, err := f.Selector(ctx, cipher, "$.visits[1].at"); return err }(),
		"wildcard node": func() error { _, err := f.ChildCount(ctx, cipher, "$.visits[*]"); return err }(),
		"not JSON":      func() error { _, err := f.Contains(ctx, cipher, json.RawMessage(`{"secret"`)); return err }(),
	} {
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Prefs orders no path: its entry has no At, and the engine answers no
	// ordering on it.
	if _, ok := reflect.TypeOf(testusers.CustomerFields.Prefs).FieldByName("At"); ok {
		t.Fatal("Prefs has an At")
	}
}

// A token is a capability and a path's keys can be a customer's data: the
// read types print and log neither, under any verb or through slog.
func TestJSONReadTypesPrintAndLogRedacted(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.CustomerFields.Profile
	sel, err := f.Selector(ctx, cipher, "$.secretkey")
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.Subtree(ctx, cipher, "$.secretkey[*]", encrypt.JSONReadOptions{WildcardBound: 2})
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.Children(ctx, cipher, "$.secretkey")
	if err != nil {
		t.Fatal(err)
	}
	hidden := append([]string{"secretkey", string(sel.Selector()), string(token)}, read.Tokens()...)
	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	for name, v := range map[string]any{"selection": sel, "read": read, "token": token, "tokens": read.Tokens()} {
		logger.Info(name, "v", v)
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			out := fmt.Sprintf(verb, v)
			for _, h := range hidden {
				if strings.Contains(out, h) {
					t.Errorf("%s printed with %s shows %q: %s", name, verb, h, out)
				}
			}
			if !strings.Contains(out, "encrypt.JSON") {
				t.Errorf("%s printed with %s does not name its type: %s", name, verb, out)
			}
		}
	}
	for _, h := range hidden {
		if strings.Contains(logged.String(), h) {
			t.Errorf("slog shows %q: %s", h, logged.String())
		}
	}
	if !strings.Contains(logged.String(), `"field":"profile"`) || !strings.Contains(logged.String(), `"tokens":3`) {
		t.Errorf("slog records no field or token count: %s", logged.String())
	}
}
