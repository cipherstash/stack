package encrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/eql"
	"github.com/cipherstash/stack/languages/golang/encrypt/gensupport"
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
	// A children read binds as its token, and a zero one binds nothing and
	// opens nothing.
	children, err := f.Children(ctx, cipher, "$.visits")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := children.Value(); err != nil || v != string(children.Token()) || children.Token() == "" {
		t.Fatalf("a children read binds as %v (%v), not its token", v, err)
	}
	var zero encrypt.JSONChildren[eql.JSONEntry]
	if _, err := zero.Value(); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a zero children read binds: %v", err)
	}
	if _, err := zero.Open(ctx, []eql.JSONEntry{eql.JSONEntry(`{}`)}); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a zero children read opens: %v", err)
	}
	if fmt.Sprint(zero) != "encrypt.JSONChildren{}" || zero.LogValue().String() != "[]" {
		t.Fatalf("a zero children read prints %v and logs %v", zero, zero.LogValue())
	}
	// A zero child has neither a key nor an index, and prints as nothing.
	var zeroChild encrypt.JSONChildValue
	if _, ok := zeroChild.Key(); ok {
		t.Fatal("a zero child has a key")
	}
	if _, ok := zeroChild.Index(); ok {
		t.Fatal("a zero child has an index")
	}
	if fmt.Sprint(zeroChild) != "encrypt.JSONChildValue{}" {
		t.Fatalf("a zero child prints %v", zeroChild)
	}
	// No entries open to no values without a request.
	if values, err := children.Open(ctx, nil); err != nil || values == nil || len(values) != 0 {
		t.Fatalf("no entries: %d values, %v", len(values), err)
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
// read types print and log neither, under any fmt verb, or through slog. A
// child a read opened is plaintext, its key included, and prints and logs
// redacted too. The three prepared reads print through one embedded type,
// each with its own name and operand.
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
	children, err := f.Children(ctx, cipher, "$.secretkey")
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		`encrypt.JSONSelection{field: "profile", path: [redacted], selector: [redacted]}`: fmt.Sprint(sel),
		`encrypt.JSONRead{field: "profile", path: [redacted], tokens: 3}`:                 fmt.Sprint(read),
		`encrypt.JSONChildren{field: "profile", path: [redacted], token: [redacted]}`:     fmt.Sprint(children),
	} {
		if got != name {
			t.Errorf("printed %s, want %s", got, name)
		}
	}
	// A child of $.secretkey, opened: a member whose key and value are
	// both plaintext.
	encrypted, err := testusers.EncryptCustomer(ctx, cipher, []testusers.Customer{{ID: 1, Profile: json.RawMessage(`{"secretkey":{"swordfishkey":"hunter2secret"}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.Selector(ctx, cipher, "$.secretkey.swordfishkey")
	if err != nil {
		t.Fatal(err)
	}
	entry := jsonEntry(t, []byte(encrypted[0].Profile), string(member.Selector()))
	opened, err := children.Open(ctx, []eql.JSONEntry{eql.JSONEntry(entry)})
	if err != nil || len(opened) != 1 {
		t.Fatalf("the child of $.secretkey: %d values, %v", len(opened), err)
	}
	child := opened[0]
	if key, ok := child.Key(); !ok || key != "swordfishkey" || string(child.JSON) != `"hunter2secret"` {
		t.Fatalf("the child opened to the key %q (%v)", key, ok)
	}
	hidden := append([]string{"secretkey", "swordfishkey", "hunter2secret", string(sel.Selector()), string(children.Token())}, read.Tokens()...)
	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	for name, v := range map[string]any{"selection": sel, "read": read, "children": children, "token": children.Token(), "tokens": read.Tokens(), "child": child} {
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

// A file generated before gensupport.JSONChildren derives a children token
// with JSONNodeToken. It is the token Children binds, and still a query's
// operand: refused through a cipher with a binding, as ChildCount is.
func TestAnOlderGeneratedChildrenTokenIsAQueryOperand(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	// The customer's profile field, declared as its generated file declares
	// it.
	declaration := gensupport.Declare("customers").
		Passthrough("id").
		EncryptInto("profile", gensupport.JSON, "JsonSearch").
		Options("profile", gensupport.TargetOptions{Ordered: []string{"$.age", "$.visits[*].at"}})
	field := gensupport.NewField[json.RawMessage](declaration, "profile")
	token, err := gensupport.JSONNodeToken(ctx, field, cipher, "children", "$.visits")
	if err != nil {
		t.Fatal(err)
	}
	children, err := testusers.CustomerFields.Profile.Children(ctx, cipher, "$.visits")
	if err != nil || children.Token() != token {
		t.Fatalf("the older file's token is not the one Children binds: %v", err)
	}
	if _, err := gensupport.JSONNodeToken(ctx, field, cipher.Bind(uint64(9)), "children", "$.visits"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("an older file's children token through a cipher with a binding: %v, want ErrEncoding", err)
	}
	if _, err := gensupport.JSONNodeToken(ctx, field, cipher, "selector", "$.visits"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("a selector as a node token: %v, want ErrEncoding", err)
	}
}

// subtreeLeafRow is the one row eql_v4.json_tree_subtree returns for a
// read of a scalar: the scalar's entry, at depth 0 below the node its token
// names.
func subtreeLeafRow(t *testing.T, entry []byte) eql.JSONEntry {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(entry, &fields); err != nil {
		t.Fatal(err)
	}
	fields["d"] = json.RawMessage(`0`)
	row, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return eql.JSONEntry(row)
}

// A document sealed through a cipher with a binding is read in part through
// the same cipher. Selector, Subtree, and Children prepare the read under
// the cipher's scopes alone. So their selector and tokens are those of a
// cipher with the same scopes and no binding. The read opens what the
// database returns under the scopes and the binding.
//
// A cipher with another binding, or none, finds the same entries and does
// not open them. A document sealed with no binding reads through a cipher
// with no binding, as before.
func TestACustomersDocumentReadsThroughACipherWithABinding(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	f := testusers.CustomerFields.Profile
	in := []testusers.Customer{{ID: 1, Profile: json.RawMessage(`{"name":"Alice","age":34,"tags":["vip"]}`)}}
	const path = "$.name"

	// selectorRead opens the entry `col -> selector` returns through
	// cipher.
	selectorRead := func(cipher *encrypt.Cipher, document []byte) (encrypt.JSONSelector, error) {
		t.Helper()
		sel, err := f.Selector(ctx, cipher, path)
		if err != nil {
			return "", err
		}
		entry := jsonEntry(t, document, string(sel.Selector()))
		if entry == nil {
			t.Fatal("the selector names no entry of the document")
		}
		row := eql.JSONEntry(entry)
		values, err := sel.Open(ctx, []*eql.JSONEntry{&row})
		if err != nil {
			return sel.Selector(), err
		}
		if len(values) != 1 || !values[0].Found || string(values[0].JSON) != `"Alice"` {
			t.Fatalf("the selection opened %+v", values)
		}
		return sel.Selector(), nil
	}
	// subtreeRead opens the row json_tree_subtree returns through cipher.
	subtreeRead := func(cipher *encrypt.Cipher, document []byte) (encrypt.JSONTokens, error) {
		t.Helper()
		read, err := f.Subtree(ctx, cipher, path, encrypt.JSONReadOptions{})
		if err != nil {
			return nil, err
		}
		// The entry the selector at the same path names is the scalar's
		// node: the row json_tree_subtree returns for it.
		sel, err := f.Selector(ctx, cipher, path)
		if err != nil {
			return nil, err
		}
		entry := jsonEntry(t, document, string(sel.Selector()))
		if entry == nil {
			t.Fatal("the selector names no entry of the document")
		}
		value, err := read.OpenOne(ctx, []eql.JSONEntry{subtreeLeafRow(t, entry)})
		if err != nil {
			return read.Tokens(), err
		}
		if !value.Found || string(value.JSON) != `"Alice"` {
			t.Fatalf("the subtree read opened %+v", value)
		}
		return read.Tokens(), nil
	}

	// childrenRead opens the one child json_tree_children returns for
	// $.tags through cipher.
	childrenRead := func(cipher *encrypt.Cipher, document []byte) (encrypt.JSONToken, error) {
		t.Helper()
		children, err := f.Children(ctx, cipher, "$.tags")
		if err != nil {
			return "", err
		}
		// The element's entry is the one carrying the elements' selector.
		sel, err := f.Selector(ctx, cipher, "$.tags[*]")
		if err != nil {
			return "", err
		}
		entry := jsonEntry(t, document, string(sel.Selector()))
		if entry == nil {
			t.Fatal("the selector names no element of the document")
		}
		values, err := children.Open(ctx, []eql.JSONEntry{eql.JSONEntry(entry)})
		if err != nil {
			return children.Token(), err
		}
		if len(values) != 1 || string(values[0].JSON) != `"vip"` {
			t.Fatalf("the child opened %d values", len(values))
		}
		if index, ok := values[0].Index(); !ok || index != 0 {
			t.Fatalf("the child is not the first element: %d %v", index, ok)
		}
		return children.Token(), nil
	}

	plain := c.DefaultKeyset()
	for _, scoped := range []struct {
		name   string
		cipher *encrypt.Cipher
	}{
		{"no scope", plain},
		{"a scope", plain.Scope(uint64(7))},
	} {
		t.Run(scoped.name, func(t *testing.T) {
			bound := scoped.cipher.Bind(uint64(9))
			encrypted, err := testusers.EncryptCustomer(ctx, bound, in)
			if err != nil {
				t.Fatal(err)
			}
			document := []byte(encrypted[0].Profile)

			selector, err := selectorRead(bound, document)
			if err != nil {
				t.Fatalf("Selector through the cipher that sealed the document: %v", err)
			}
			tokens, err := subtreeRead(bound, document)
			if err != nil {
				t.Fatalf("Subtree through the cipher that sealed the document: %v", err)
			}
			token, err := childrenRead(bound, document)
			if err != nil {
				t.Fatalf("Children through the cipher that sealed the document: %v", err)
			}
			// The operands are those of the cipher's scopes alone.
			unbound, err := f.Selector(ctx, scoped.cipher, path)
			if err != nil || unbound.Selector() != selector {
				t.Errorf("the bound cipher's selector is not its scopes' own: %v", err)
			}
			unboundRead, err := f.Subtree(ctx, scoped.cipher, path, encrypt.JSONReadOptions{})
			if err != nil || !slices.Equal(unboundRead.Tokens(), tokens) {
				t.Errorf("the bound cipher's tokens are not its scopes' own: %v", err)
			}
			// A binding part Bind refuses is reported when the read is
			// prepared, not when it opens.
			if _, err := f.Selector(ctx, scoped.cipher.Bind(""), path); !errors.Is(err, encrypt.ErrEncoding) {
				t.Errorf("Selector through a cipher with an empty binding: %v, want ErrEncoding", err)
			}
			if _, err := f.Subtree(ctx, scoped.cipher.Bind(""), path, encrypt.JSONReadOptions{}); !errors.Is(err, encrypt.ErrEncoding) {
				t.Errorf("Subtree through a cipher with an empty binding: %v, want ErrEncoding", err)
			}
			unboundChildren, err := f.Children(ctx, scoped.cipher, "$.tags")
			if err != nil || unboundChildren.Token() != token {
				t.Errorf("the bound cipher's children token is not its scopes' own: %v", err)
			}
			if _, err := f.Children(ctx, scoped.cipher.Bind(""), "$.tags"); !errors.Is(err, encrypt.ErrEncoding) {
				t.Errorf("Children through a cipher with an empty binding: %v, want ErrEncoding", err)
			}

			// An ordered path's accessor prepares its selection the same way.
			atAge, err := f.At.Age.Selector(ctx, bound)
			if err != nil {
				t.Fatalf("At.Age.Selector through a cipher with a binding: %v", err)
			}
			if want, err := f.Selector(ctx, scoped.cipher, "$.age"); err != nil || atAge.Selector() != want.Selector() {
				t.Errorf("At.Age's selector is not its scopes' own: %v", err)
			}

			// A cipher with the same scopes and another binding, or none,
			// finds the entry and does not open it: the entry was sealed
			// under the binding, so ZeroKMS refuses its data key
			// (ErrForbidden), as it refuses a record's.
			for whose, other := range map[string]*encrypt.Cipher{
				"no binding":  scoped.cipher,
				"another row": scoped.cipher.Bind(uint64(10)),
			} {
				if _, err := selectorRead(other, document); !errors.Is(err, encrypt.ErrForbidden) {
					t.Errorf("%s: Selector opened the entry, or not as ErrForbidden: %v", whose, err)
				}
				if _, err := subtreeRead(other, document); !errors.Is(err, encrypt.ErrForbidden) {
					t.Errorf("%s: Subtree opened the row, or not as ErrForbidden: %v", whose, err)
				}
				if _, err := childrenRead(other, document); !errors.Is(err, encrypt.ErrForbidden) {
					t.Errorf("%s: Children opened the child, or not as ErrForbidden: %v", whose, err)
				}
			}

			// A query opens nothing, so it has no use for a binding, and a
			// query through a cipher with one is still refused. So is a
			// child count's token. That token is a query's operand too.
			for name, err := range map[string]error{
				"Contains":    func() error { _, err := f.Contains(ctx, bound, json.RawMessage(`{"name":"Alice"}`)); return err }(),
				"ContainedBy": func() error { _, err := f.ContainedBy(ctx, bound, json.RawMessage(`{"name":"Alice"}`)); return err }(),
				"EqAt":        func() error { _, err := f.EqAt(ctx, bound, path, "Alice"); return err }(),
				"At.Age.Lt":   func() error { _, err := f.At.Age.Lt(ctx, bound, 40); return err }(),
				"Match": func() error {
					_, err := f.Match(ctx, bound, `$.age < 40`, map[string]any{}, encrypt.JSONReadOptions{})
					return err
				}(),
				"Elements.Visits.Match": func() error {
					_, err := f.Elements.Visits.Match(ctx, bound, encrypt.JSONReadOptions{}, encrypt.AtPath(testusers.CustomerPaths.Profile.Visits.At).Gt(1))
					return err
				}(),
				"ChildCount": func() error { _, err := f.ChildCount(ctx, bound, path); return err }(),
			} {
				if !errors.Is(err, encrypt.ErrEncoding) {
					t.Errorf("%s through a cipher with a binding: %v, want ErrEncoding", name, err)
				}
			}

			// A document sealed with no binding reads through a cipher with
			// no binding, and not through one with a binding.
			plainEncrypted, err := testusers.EncryptCustomer(ctx, scoped.cipher, in)
			if err != nil {
				t.Fatal(err)
			}
			plainDocument := []byte(plainEncrypted[0].Profile)
			if _, err := selectorRead(scoped.cipher, plainDocument); err != nil {
				t.Errorf("Selector of a document sealed with no binding: %v", err)
			}
			if _, err := subtreeRead(scoped.cipher, plainDocument); err != nil {
				t.Errorf("Subtree of a document sealed with no binding: %v", err)
			}
			if _, err := childrenRead(scoped.cipher, plainDocument); err != nil {
				t.Errorf("Children of a document sealed with no binding: %v", err)
			}
			if _, err := childrenRead(bound, plainDocument); !errors.Is(err, encrypt.ErrForbidden) {
				t.Errorf("a bound cipher's Children opened a document sealed with no binding: %v", err)
			}
			if _, err := selectorRead(bound, plainDocument); !errors.Is(err, encrypt.ErrForbidden) {
				t.Errorf("a bound cipher's Selector opened a document sealed with no binding: %v", err)
			}
			if _, err := subtreeRead(bound, plainDocument); !errors.Is(err, encrypt.ErrForbidden) {
				t.Errorf("a bound cipher's Subtree opened a document sealed with no binding: %v", err)
			}
		})
	}
}
