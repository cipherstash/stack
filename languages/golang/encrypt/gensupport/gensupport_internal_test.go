package gensupport

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

func TestDeclarationLowersToTheEnginesPlan(t *testing.T) {
	d := Declare("users").
		Passthrough("id").
		EncryptIndex("age", UInt32, encrypt.Equality, encrypt.Ore).
		EncryptIndex("email", String, encrypt.Equality, encrypt.Match()).
		Encrypt("notes", String).
		Index("score", Int64, encrypt.Ope).
		Omit("internal")
	plan, err := d.plan()
	if err != nil {
		t.Fatal(err)
	}
	want := &record.Plan{Context: []string{"users"}, Fields: []record.Field{
		{Name: "age", Kind: record.UInt32, Outputs: []record.Output{record.Ciphertext, record.Equality, record.Ore}},
		{Name: "email", Kind: record.String, Outputs: []record.Output{record.Ciphertext, record.Equality, record.Match}},
		{Name: "notes", Kind: record.String, Outputs: []record.Output{record.Ciphertext}},
		{Name: "score", Kind: record.Int64, Outputs: []record.Output{record.Ope}},
	}}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %+v", plan)
	}
	// Passthrough and omitted fields stay on the host; the engine never
	// hears of them.
	if plan.Field("id") != nil || plan.Field("internal") != nil {
		t.Fatal("a passthrough or omitted field reached the plan")
	}
	// An opaque declaration is one untyped field.
	op, err := DeclareOpaque("documents/v2/body").plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(op.Fields) != 1 || op.Fields[0].Name != OpaqueField || op.Fields[0].Kind != record.Bytes || op.Descriptor(op.Fields[0]) != "documents/v2/body/value" {
		t.Fatalf("opaque plan = %+v", op)
	}
	// Identity pins the context part.
	id, err := Declare("individuals").Encrypt("medicare_number", String).Identity("medicare_number", "medicare_no").plan()
	if err != nil {
		t.Fatal(err)
	}
	if id.Descriptor(id.Fields[0]) != "individuals/medicare_no" {
		t.Fatalf("identity: %q", id.Descriptor(id.Fields[0]))
	}
}

func TestDeclarationRefusals(t *testing.T) {
	cases := map[string]Declaration{
		"empty context":             Declare(""),
		"context not a label":       Declare("users/1x"),
		"field twice":               Declare("u").Encrypt("a", String).Encrypt("a", String),
		"no name":                   Declare("u").Encrypt("", String),
		"indexed with no index":     Declare("u").EncryptIndex("a", String),
		"opaque with another field": DeclareOpaque("u").Encrypt("a", String),
		"identity of no field":      Declare("u").Encrypt("a", String).Identity("b", "x"),
		"seals nothing":             Declare("u").Passthrough("id"),
		"EQL not available":         Declare("u").EncryptInto("email", String, "TextEq"),
		"json index":                Declare("u").EncryptIndex("a", String, encrypt.JSON()),
		"name not a label":          Declare("u").Encrypt("1a", String),
	}
	for name, d := range cases {
		if _, err := d.plan(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Declare("u").EncryptInto("email", String, "TextEq").plan(); err == nil || !strings.Contains(err.Error(), "EQL types are not available yet") {
		t.Fatalf("encrypt_into: %v", err)
	}
}

func TestConvertStaysWithinAFamily(t *testing.T) {
	var u8 uint8
	if err := convert(uint32(7), &u8); err != nil || u8 != 7 {
		t.Fatalf("uint32 -> uint8: %v %d", err, u8)
	}
	if err := convert(uint32(300), &u8); err == nil {
		t.Fatal("300 fit a uint8")
	}
	var i int
	if err := convert(int64(-5), &i); err != nil || i != -5 {
		t.Fatalf("int64 -> int: %v %d", err, i)
	}
	if err := convert(uint64(1<<63), &i); err == nil {
		t.Fatal("2^63 fit an int")
	}
	var u uint
	if err := convert(int32(-1), &u); err == nil {
		t.Fatal("-1 fit a uint")
	}
	var s string
	if err := convert(int32(1), &s); err == nil {
		t.Fatal("an integer became a string")
	}
	var f32 float32
	if err := convert(float64(1.5), &f32); err != nil || f32 != 1.5 {
		t.Fatalf("float64 -> float32: %v %v", err, f32)
	}
	var b []byte
	src := []byte{1, 2}
	if err := convert(src, &b); err != nil {
		t.Fatal(err)
	}
	src[0] = 9
	if b[0] != 1 {
		t.Fatal("convert aliased the decoded slice")
	}
	var tags []string
	if err := convert([]any{"a", "b"}, &tags); err != nil || !reflect.DeepEqual(tags, []string{"a", "b"}) {
		t.Fatalf("[]string: %v %v", err, tags)
	}
	if err := convert([]any{"a", 1}, &tags); err == nil {
		t.Fatal("a mixed array became []string")
	}
	var vals Values
	obj := vcvalue.Object{{Key: "title", Value: "x"}, {Key: "inner", Value: vcvalue.Object{{Key: "n", Value: int64(1)}}}}
	if err := convert(obj, &vals); err != nil {
		t.Fatal(err)
	}
	if vals["title"] != "x" || vals["inner"].(Values)["n"] != int64(1) {
		t.Fatalf("Values = %#v", vals)
	}
	type unsupported struct{ A int }
	var x unsupported
	if err := convert(obj, &x); err == nil {
		t.Fatal("a struct target was accepted")
	}
	// An opaque value decodes straight into the generated shape type.
	type shape struct {
		Title string            `json:"title"`
		N     int32             `json:"n"`
		Tags  []string          `json:"tags"`
		Inner map[string]string `json:"inner"`
	}
	encoded, err := opaqueBytes(shape{Title: "x", N: 4, Tags: []string{"a"}, Inner: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	var back shape
	if err := Opaque(Values{OpaqueField: encoded}, &back); err != nil || back.Title != "x" || back.N != 4 || back.Inner["k"] != "v" {
		t.Fatalf("Opaque: %v %+v", err, back)
	}
	if err := Opaque(Values{OpaqueField: "not bytes"}, &back); err == nil {
		t.Fatal("Opaque accepted a string")
	}
	if err := Opaque(Values{}, &back); err == nil {
		t.Fatal("Opaque found a missing field")
	}
	// A passthrough value of any type comes back as it is.
	when := time.Date(2026, 10, 6, 1, 2, 3, 0, time.UTC)
	gotTime, err := Get[time.Time](Values{"at": when}, "at")
	if err != nil || !gotTime.Equal(when) {
		t.Fatalf("Get[time.Time] = %v %v", gotTime, err)
	}
	type defined string
	gotDefined, err := Get[defined](Values{"d": defined("x")}, "d")
	if err != nil || gotDefined != "x" {
		t.Fatalf("Get[defined] = %v %v", gotDefined, err)
	}
	if _, err := Get[defined](Values{"d": "x"}, "d"); err == nil {
		t.Fatal("Get converted a wire string into a defined type; the generated code does that")
	}
	got, err := Get[uint8](Values{"age": uint32(3)}, "age")
	if err != nil || got != 3 {
		t.Fatalf("Get = %v %v", got, err)
	}
	if _, err := Get[uint8](Values{}, "age"); err == nil {
		t.Fatal("Get found a missing field")
	}
	p, err := Passthrough[int64](Record{"id": {Value: int64(4)}}, "id")
	if err != nil || p != 4 {
		t.Fatalf("Passthrough = %v %v", p, err)
	}
	if _, err := Passthrough[int64](Record{"id": {Value: "4"}}, "id"); err == nil {
		t.Fatal("Passthrough converted a string")
	}
}

type user struct {
	ID    int64
	Email string
	Note  string
}

type encryptedUser struct {
	ID    int64
	Email Output
	Note  encrypt.Ciphertext
}

func userCodec() *Codec[user, encryptedUser] {
	return New(Generated[user, encryptedUser]{
		TypeName:    "User",
		Declaration: Declare("users").Passthrough("id").EncryptIndex("email", String, encrypt.Equality).Encrypt("note", String).Omit("internal"),
		Source:      func(u user) Values { return Values{"id": u.ID, "email": u.Email, "note": u.Note} },
		Seal: func(rec Record) (encryptedUser, error) {
			id, err := Passthrough[int64](rec, "id")
			return encryptedUser{ID: id, Email: rec["email"], Note: rec["note"].Ciphertext}, err
		},
		Open: func(e encryptedUser) Record {
			return Record{"id": {Value: e.ID}, "email": {Ciphertext: e.Email.Ciphertext}, "note": {Ciphertext: e.Note}}
		},
		Value: func(e encryptedUser, vals Values) (user, error) {
			var u user
			var err error
			if u.ID, err = Get[int64](vals, "id"); err != nil {
				return user{}, err
			}
			if u.Email, err = Get[string](vals, "email"); err != nil {
				return user{}, err
			}
			if u.Note, err = Get[string](vals, "note"); err != nil {
				return user{}, err
			}
			return u, nil
		},
	})
}

func TestSplitFailsClosedInBothDirections(t *testing.T) {
	c := userCodec()
	if c.err != nil {
		t.Fatal(c.err)
	}
	row, keep, err := c.split(Values{"id": int64(1), "email": "a", "note": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(row, record.Source{"email": "a", "note": "b"}) || !reflect.DeepEqual(keep, map[string]any{"id": int64(1)}) {
		t.Fatalf("split = %v %v", row, keep)
	}
	if _, _, err := c.split(Values{"id": int64(1), "email": "a"}); err == nil || !strings.Contains(err.Error(), `no field "note"`) {
		t.Fatalf("missing field: %v", err)
	}
	if _, _, err := c.split(Values{"id": int64(1), "email": "a", "note": "b", "stray": 1}); err == nil || !strings.Contains(err.Error(), `"stray"`) {
		t.Fatalf("extra field: %v", err)
	}
}

func TestNewReportsAnIncompleteFileAndABadDeclarationOnFirstUse(t *testing.T) {
	c := New(Generated[user, encryptedUser]{TypeName: "User", Declaration: Declare("users").Encrypt("a", String)})
	if _, err := c.Encrypt(t.Context(), nil, nil); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete: %v", err)
	}
	bad := userCodec()
	bad.g.Declaration = Declare("")
	bad.plan, bad.err = bad.g.Declaration.plan()
	if _, err := bad.Decrypt(t.Context(), nil, nil); err == nil {
		t.Fatal("a bad declaration was not reported")
	}
	// No cipher: a programming error, reported, not a nil dereference.
	if _, err := userCodec().Encrypt(t.Context(), nil, []user{{}}); err == nil {
		t.Fatal("a nil cipher was accepted")
	}
	if _, err := userCodec().Decrypt(t.Context(), nil, []encryptedUser{{}}); err == nil {
		t.Fatal("a nil decrypter was accepted")
	}
}
