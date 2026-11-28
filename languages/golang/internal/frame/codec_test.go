package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

// marshalUnmarshal encodes v as transport bytes and decodes the bytes again.
// Every case below uses it.
func marshalUnmarshal(t *testing.T, v any) any {
	t.Helper()
	buf, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal(%#v): %v", v, err)
	}
	got, err := Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return got
}

func TestReflectNatives(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"nil", nil, nil},
		{"bool", true, true},
		{"int", 42, int64(42)},                 // an int is written as Int64
		{"int8", int8(-5), int8(-5)},           // exact signed width
		{"int16", int16(-300), int16(-300)},    // exact signed width
		{"int32", int32(-9), int32(-9)},        // Int32, exact width
		{"int64", int64(-9), int64(-9)},        // Int64
		{"uint8", uint8(7), uint8(7)},          // exact unsigned width
		{"uint16", uint16(300), uint16(300)},   // exact unsigned width
		{"uint32", uint32(7), uint32(7)},       // Uint32, exact width
		{"uint", uint(7), uint64(7)},           // a uint is always written as Uint64
		{"uint64-small", uint64(7), uint64(7)}, // a uint64 is written as Uint64
		{"uint64-max", uint64(math.MaxUint64), uint64(math.MaxUint64)},
		{"float32", float32(1.5), float32(1.5)}, // Float32, exact width
		{"float", 1.5, 1.5},                     // a float64 is written as Float64
		{"string", "hi", "hi"},
		{"bytes", []byte{1, 2, 3}, []byte{1, 2, 3}},
		{"slice", []int{1, 2}, []any{int64(1), int64(2)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := marshalUnmarshal(t, c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestReflectStructTags(t *testing.T) {
	type inner struct {
		A int64 `vc:"a"`
	}
	type outer struct {
		Name    string `vc:"name"`
		Skipped string `vc:"-"`
		hidden  string //nolint:unused // unexported, must be skipped
		Nested  inner
	}
	got := marshalUnmarshal(t, outer{Name: "x", Skipped: "no", hidden: "no", Nested: inner{A: 1}})
	want := Object{
		{Key: "name", Value: "x"},
		{Key: "Nested", Value: Object{{Key: "a", Value: int64(1)}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReflectMapSortsKeys(t *testing.T) {
	// Go iterates over a map in a random order. The encoder must sort the
	// keys, so that equal maps have the same structure. The decoder keeps
	// the sorted order.
	got := marshalUnmarshal(t, map[string]int64{"c": 3, "a": 1, "b": 2})
	want := Object{
		{Key: "a", Value: int64(1)},
		{Key: "b", Value: int64(2)},
		{Key: "c", Value: int64(3)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReflectPointerDeref(t *testing.T) {
	n := int64(5)
	if got := marshalUnmarshal(t, &n); !reflect.DeepEqual(got, int64(5)) {
		t.Fatalf("got %#v, want int64(5)", got)
	}
	var nilPtr *int64
	if got := marshalUnmarshal(t, nilPtr); got != nil {
		t.Fatalf("nil pointer should decode as nil, got %#v", got)
	}
}

// point implements Encryptable, so it writes itself.
type point struct{ X, Y int64 }

func (p point) EncryptValue(enc Encoder) error {
	m := enc.Map()
	m.Field("x").Int64(p.X)
	m.Field("y").Int64(p.Y)
	return m.End()
}

func TestEncryptableImpl(t *testing.T) {
	got := marshalUnmarshal(t, point{X: 1, Y: 2})
	want := Object{{Key: "x", Value: int64(1)}, {Key: "y", Value: int64(2)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// TestEncryptableNested checks that the encoder calls an Encryptable that it
// reaches through reflection, as a struct field. The top level is not the
// only place.
func TestEncryptableNested(t *testing.T) {
	type shape struct {
		Origin point
	}
	got := marshalUnmarshal(t, shape{Origin: point{X: 3, Y: 4}})
	want := Object{
		{Key: "Origin", Value: Object{
			{Key: "x", Value: int64(3)},
			{Key: "y", Value: int64(4)},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestEncoderChannels(t *testing.T) {
	// Call the Encoder methods directly, including a nested Seq.
	buf, err := Marshal(seqBuilder{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []any{
		nil, true,
		float64(1.5), float32(0.5),
		int32(-1), int64(-1),
		uint32(math.MaxUint32), uint64(math.MaxUint64),
		"s", []byte{9},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

type seqBuilder struct{}

func (seqBuilder) EncryptValue(enc Encoder) error {
	s := enc.Seq()
	s.Elem().Null()
	s.Elem().Bool(true)
	s.Elem().Float64(1.5)
	s.Elem().Float32(0.5)
	s.Elem().Int32(-1)
	s.Elem().Int64(-1)
	s.Elem().Uint32(math.MaxUint32)
	s.Elem().Uint64(math.MaxUint64)
	s.Elem().String("s")
	s.Elem().Bytes([]byte{9})
	return s.End()
}

func TestInvalidUTF8StringRejected(t *testing.T) {
	if _, err := Marshal(string([]byte{0xff})); err == nil {
		t.Fatal("expected invalid UTF-8 string to be rejected")
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	if _, err := Unmarshal([]byte{0x7f}); err == nil {
		t.Fatal("unknown tag must be rejected")
	}
	// The input has bytes after a complete value.
	if _, err := Unmarshal([]byte{0x00, 0x00}); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
}

// TestPlainPassthroughRoundTrip checks that a value wrapped in Plain is
// encoded as passthrough, and decodes as Plain{V: ...}. A caller can
// therefore tell that the value was not encrypted.
func TestPlainPassthroughRoundTrip(t *testing.T) {
	got := marshalUnmarshal(t, map[string]any{
		"id":    Plain{V: int64(42)},
		"email": "ada@example.com",
	})
	want := Object{
		{Key: "email", Value: "ada@example.com"},
		{Key: "id", Value: Plain{V: int64(42)}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// A Plain around a whole subtree makes every value in the subtree
// passthrough.
func TestPlainPassthroughSubtree(t *testing.T) {
	got := marshalUnmarshal(t, Plain{V: []any{int64(1), "two", true}})
	want := Plain{V: []any{int64(1), "two", true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// passthroughBuilder calls Encoder.Passthrough directly: at the root, for a
// sequence element, and for a map entry.
type passthroughBuilder struct{}

func (passthroughBuilder) EncryptValue(enc Encoder) error {
	s := enc.Seq()
	s.Elem().Passthrough().Int64(7) // passthrough sequence element
	s.Elem().String("sealed")
	return s.End()
}

func TestEncoderPassthroughChannel(t *testing.T) {
	got := marshalUnmarshal(t, passthroughBuilder{})
	want := []any{Plain{V: int64(7)}, "sealed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestUnmarshalRejectsTruncatedPassthrough(t *testing.T) {
	// A passthrough tag, 0xF2, with no value node after it.
	if _, err := Unmarshal([]byte{0xF2}); err == nil {
		t.Fatal("truncated passthrough node must be rejected")
	}
}

func TestUnmarshalRejectsPassthroughDepthBomb(t *testing.T) {
	// Input that nests only passthrough tags must reach the depth limit.
	bytes := make([]byte, 0, 200)
	for range 130 { // > maxDepth (128)
		bytes = append(bytes, 0xF2)
	}
	bytes = append(bytes, 0x00) // NULL
	if _, err := Unmarshal(bytes); err == nil {
		t.Fatal("over-deep passthrough nesting must be rejected")
	}
}

// A passthrough node of a ciphertext keeps its readable value when it is
// encoded and decoded. The value comes back wrapped in Plain. A later encode
// therefore cannot treat it as a ciphertext map or sequence.
func TestCipherTextPassthroughTransportRoundTrip(t *testing.T) {
	ct := map[string]any{
		"id":    Plain{V: int64(42)},
		"email": sealed{9, 9, 9},
	}
	buf, err := MarshalCipherText(testLeaves(), ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(testLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

func TestCipherTextTransportRoundTrip(t *testing.T) {
	ct := map[string]any{
		"a": sealed{9, 9, 9},
		"b": []any{sealed{1}, sealedEmptySeq{2}},
	}
	buf, err := MarshalCipherText(testLeaves(), ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(testLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

// A plaintext value that is not marked is refused where a ciphertext node
// belongs. A passthrough value must be wrapped in Plain, so no value is left
// unencrypted by accident.
func TestCipherTextRejectsBarePlaintext(t *testing.T) {
	if _, err := MarshalCipherText(testLeaves(), map[string]any{"x": "oops"}); err == nil {
		t.Fatal("bare plaintext in ciphertext position must be rejected")
	}
	if _, err := MarshalCipherText(testLeaves(), []byte{1, 2, 3}); err == nil {
		t.Fatal("bare []byte must be rejected (use a leaf type or Plain)")
	}
}

// A struct with no exported fields must be refused. time.Time is the usual
// example. Sealing such a struct as an empty map would lose its value with
// no error.
func TestMarshalRejectsZeroExportedFieldStruct(t *testing.T) {
	type opaque struct {
		hidden int //nolint:unused // unexported on purpose
	}
	if _, err := Marshal(opaque{hidden: 1}); err == nil {
		t.Fatal("struct with no exported fields must be rejected")
	}
	// A struct whose fields all have a vc:"-" tag is accepted, because the
	// caller asked for the empty encoding. The empty struct is accepted too.
	type skipped struct {
		ID int `vc:"-"`
	}
	if _, err := Marshal(skipped{ID: 1}); err != nil {
		t.Fatalf("all-skipped struct should encode: %v", err)
	}
	if _, err := Marshal(struct{}{}); err != nil {
		t.Fatalf("empty struct should encode: %v", err)
	}
}

// Object is what a map decodes as. An Object must be encoded as a map again,
// at the root and inside other values. A program that decrypts a record and
// encrypts it again then keeps the structure of the record.
func TestObjectReencodesWithObjectFraming(t *testing.T) {
	o := Object{
		{Key: "b", Value: int64(2)},
		{Key: "a", Value: int64(1)},
	}
	got := marshalUnmarshal(t, o)
	if !reflect.DeepEqual(got, o) {
		t.Fatalf("root Object: got %#v, want %#v", got, o)
	}

	nested := []any{o}
	got = marshalUnmarshal(t, nested)
	want := []any{o}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nested Object: got %#v, want %#v", got, want)
	}
}

// An Object wrapped in Plain inside a ciphertext must keep its structure
// when it is encoded and decoded as passthrough.
func TestCipherTextPassthroughObjectRoundTrip(t *testing.T) {
	o := Object{{Key: "id", Value: int64(42)}}
	buf, err := MarshalCipherText(testLeaves(), Plain{V: o})
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(testLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, Plain{V: o}) {
		t.Fatalf("got %#v, want Plain{V: %#v}", got, o)
	}
}

// A [N]byte must be written as one Bytes value, as a []byte is. Writing each
// byte as an element would produce a ciphertext structure that no other
// encoder writes.
func TestByteArrayEncodesAsBytes(t *testing.T) {
	got := marshalUnmarshal(t, [4]byte{1, 2, 3, 4})
	if !reflect.DeepEqual(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("got %#v, want []byte{1,2,3,4}", got)
	}
	type hashed struct {
		Hash [4]byte
	}
	got = marshalUnmarshal(t, hashed{Hash: [4]byte{9, 8, 7, 6}})
	want := Object{{Key: "Hash", Value: []byte{9, 8, 7, 6}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// nilEncryptable panics if EncryptValue is called on a nil receiver. The
// encoder must detect a nil pointer and never make that call.
type nilEncryptable struct{ n int }

func (e *nilEncryptable) EncryptValue(enc Encoder) error {
	enc.Int64(int64(e.n)) // dereferences e
	return nil
}

// A nil pointer of a type that implements Encryptable must be encoded as
// Null. The encoder must not call the method on a nil receiver.
func TestTypedNilEncryptableEncodesNull(t *testing.T) {
	var p *nilEncryptable
	if got := marshalUnmarshal(t, p); got != nil {
		t.Fatalf("typed nil at root: got %#v, want nil", got)
	}
	got := marshalUnmarshal(t, []any{p})
	if !reflect.DeepEqual(got, []any{nil}) {
		t.Fatalf("typed nil in slice: got %#v, want []any{nil}", got)
	}
}

// A pointer cycle must fail with an error. The encoder must not recurse
// until the stack overflows.
func TestMarshalRejectsPointerCycle(t *testing.T) {
	var x any
	x = &x
	if _, err := Marshal(x); err == nil {
		t.Fatal("pointer cycle must be rejected")
	}
}

// MarshalCipherText must refuse a passthrough value that is deeper than the
// depth limit. Otherwise it would write bytes that UnmarshalCipherText
// always refuses.
func TestMarshalCipherTextRejectsPassthroughBeyondDepthBudget(t *testing.T) {
	// 129 nested []any put the value inside the Plain deeper than maxDepth
	// (128).
	var deep any = Plain{V: int64(1)}
	for range 129 {
		deep = []any{deep}
	}
	if _, err := MarshalCipherText(testLeaves(), deep); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("over-deep passthrough must be rejected with ErrTooDeep at encode time, got %v", err)
	}

	// A value one level less deep still encodes and decodes, so the limit is
	// exact.
	var ok any = Plain{V: int64(1)}
	for range 127 {
		ok = []any{ok}
	}
	buf, err := MarshalCipherText(testLeaves(), ok)
	if err != nil {
		t.Fatalf("MarshalCipherText at the bound: %v", err)
	}
	if _, err := UnmarshalCipherText(testLeaves(), buf); err != nil {
		t.Fatalf("UnmarshalCipherText at the bound: %v", err)
	}
}

// The tests below give malformed input to the two decoders. The tests build
// the transport bytes by hand, because no Go encoder writes these bytes.

func u32le(n int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b
}

// ctEntry returns the bytes of one entry of a ciphertext map: the key, then
// a ctSingle leaf of one byte.
func ctEntry(key string) []byte {
	e := append(u32le(len(key)), key...)
	e = append(e, 0x01) // ctSingle
	e = append(e, u32le(1)...)
	return append(e, 0xAB)
}

// decodeCipherText refuses a duplicate map key. A Go map cannot have one, so
// only bytes built by hand or written by another language can contain one.
func TestUnmarshalCipherTextRejectsDuplicateKey(t *testing.T) {
	dup := []byte{0x04} // ctMap
	dup = append(dup, u32le(2)...)
	dup = append(dup, ctEntry("a")...)
	dup = append(dup, ctEntry("a")...)
	if _, err := UnmarshalCipherText(testLeaves(), dup); err == nil {
		t.Fatal("duplicate ciphertext map key must be rejected")
	}

	// As a control, the same bytes with distinct keys decode.
	ok := []byte{0x04}
	ok = append(ok, u32le(2)...)
	ok = append(ok, ctEntry("a")...)
	ok = append(ok, ctEntry("b")...)
	if _, err := UnmarshalCipherText(testLeaves(), ok); err != nil {
		t.Fatalf("distinct keys should decode: %v", err)
	}
}

// Unmarshal applies its depth limit and its check on hostile counts to
// arrays and to objects. The Rust codec tests the same cases.
func TestUnmarshalRejectsArrayAndObjectBombs(t *testing.T) {
	// Too deep: 130 nested arrays of one element each, more than maxDepth
	// (128).
	var deep []byte
	for range 130 {
		deep = append(deep, 0xF0) // tagArray
		deep = append(deep, u32le(1)...)
	}
	deep = append(deep, 0x00) // tagNull
	if _, err := Unmarshal(deep); err == nil {
		t.Fatal("array depth bomb must be rejected")
	}

	// Too deep: 130 nested objects of one entry each.
	var deepObj []byte
	for range 130 {
		deepObj = append(deepObj, 0xF1) // tagObject
		deepObj = append(deepObj, u32le(1)...)
		deepObj = append(deepObj, u32le(1)...)
		deepObj = append(deepObj, 'k')
	}
	deepObj = append(deepObj, 0x00)
	if _, err := Unmarshal(deepObj); err == nil {
		t.Fatal("object depth bomb must be rejected")
	}

	// A hostile count: an array that declares the largest 32-bit count and
	// has no bytes after it.
	if _, err := Unmarshal([]byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("hostile array count must be rejected")
	}
}

// UnmarshalCipherText has its own depth limit, check on hostile counts, and
// check for bytes after the tree. The recursion of UnmarshalCipherText is
// separate from that of the value decoder.
func TestUnmarshalCipherTextRejectsMalformed(t *testing.T) {
	// Too deep: 130 nested ctSeq nodes of one element each.
	var deep []byte
	for range 130 {
		deep = append(deep, 0x03) // ctSeq
		deep = append(deep, u32le(1)...)
	}
	deep = append(deep, ctEntry("")[4:]...) // a bare ctSingle leaf
	if _, err := UnmarshalCipherText(testLeaves(), deep); err == nil {
		t.Fatal("ciphertext depth bomb must be rejected")
	}

	// A hostile count.
	if _, err := UnmarshalCipherText(testLeaves(), []byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("hostile ciphertext count must be rejected")
	}

	// Bytes after a complete node.
	leaf := append([]byte{0x01}, u32le(1)...)
	leaf = append(leaf, 0xAB, 0xFF) // one extra byte
	if _, err := UnmarshalCipherText(testLeaves(), leaf); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}

	// An unknown tag.
	if _, err := UnmarshalCipherText(testLeaves(), []byte{0x7F}); err == nil {
		t.Fatal("unknown ciphertext tag must be rejected")
	}
}

// A kind with no encoding reaches the default case of encodeReflect.
// Examples are a channel, a function, and a complex number. The encode must
// return an error. The encode must not panic or write bytes.
func TestMarshalRejectsUnsupportedKind(t *testing.T) {
	if _, err := Marshal(make(chan int)); err == nil {
		t.Fatal("a channel value has no encoding and must be rejected")
	}
	if _, err := Marshal(func() {}); err == nil {
		t.Fatal("a func value has no encoding and must be rejected")
	}
	if _, err := Marshal(complex(1, 2)); err == nil {
		t.Fatal("a complex value has no encoding and must be rejected")
	}
}

// encodeMap refuses a map whose keys are not strings. The transport encoding
// writes a key as UTF-8 bytes, so it has no form for a key of another type.
func TestMarshalRejectsNonStringMapKey(t *testing.T) {
	if _, err := Marshal(map[int]string{1: "a"}); err == nil {
		t.Fatal("map with non-string keys must be rejected")
	}
}

// The encoder applies the depth limit too: a Go value that is nested too
// deep fails the encode. Other tests give the decoders input that is too
// deep. This test reaches the same limit from the encoder.
func TestMarshalRejectsDepthBomb(t *testing.T) {
	var v any = int64(0)
	for range 130 { // > maxDepth (128)
		v = []any{v}
	}
	if _, err := Marshal(v); err == nil {
		t.Fatal("over-deep value must be rejected at encode time")
	}
}

// A duplicate object key in the encoded bytes must be refused, as the
// ciphertext decoder refuses a duplicate ctMap key. If an Object with a
// duplicate key were encoded again through a Go map, one entry would be lost
// with no error. Only bytes built by hand can contain a duplicate key,
// because the encoder writes unique keys in sorted order.
func TestUnmarshalRejectsDuplicateObjectKey(t *testing.T) {
	key := []byte{1, 0, 0, 0, 'a'}
	var buf []byte
	buf = append(buf, 0xF1, 2, 0, 0, 0) // tagObject, count 2
	buf = append(buf, key...)
	buf = append(buf, 0x00) // Null value
	buf = append(buf, key...)
	buf = append(buf, 0x00)
	if _, err := Unmarshal(buf); err == nil {
		t.Fatal("an object with a duplicate key must be rejected")
	}

	// As a control, the same bytes with distinct keys decode.
	var ok []byte
	ok = append(ok, 0xF1, 2, 0, 0, 0)
	ok = append(ok, 1, 0, 0, 0, 'a', 0x00)
	ok = append(ok, 1, 0, 0, 0, 'b', 0x00)
	if _, err := Unmarshal(ok); err != nil {
		t.Fatalf("distinct keys must decode: %v", err)
	}
}

// skipsValue writes a key, or asks for an element, and never writes the
// value. Field and Elem must report that mistake at encode. Without their
// check, the mistake would appear only as ErrMalformed at decode.
type skipsValue struct{ inSeq bool }

func (s skipsValue) EncryptValue(enc Encoder) error {
	if s.inSeq {
		q := enc.Seq()
		q.Elem() // claimed, never written
		q.Elem().Int64(1)
		return q.End()
	}
	m := enc.Map()
	m.Field("a") // key written, value never written
	m.Field("b").Int64(1)
	return m.End()
}

// lastValueMissing tests the check in End. The value of the last entry is
// the one that is skipped, so no later call to Field or Elem can report it.
type lastValueMissing struct{ inSeq bool }

func (s lastValueMissing) EncryptValue(enc Encoder) error {
	if s.inSeq {
		q := enc.Seq()
		q.Elem().Int64(1)
		q.Elem() // claimed, never written
		return q.End()
	}
	m := enc.Map()
	m.Field("a").Int64(1)
	m.Field("b") // key written, value never written
	return m.End()
}

// unclosedNested writes a scalar inside a nested container and never calls
// End on the container. The slot of the container is incomplete, although a
// value deeper in the tree is complete. The check must therefore count each
// slot separately, not the whole encode.
type unclosedNested struct{ inSeq bool }

func (u unclosedNested) EncryptValue(enc Encoder) error {
	if u.inSeq {
		q := enc.Seq()
		inner := q.Elem().Seq()
		inner.Elem().Int64(1) // inner.End() never called
		q.Elem().Int64(2)
		return q.End()
	}
	m := enc.Map()
	inner := m.Field("a").Seq()
	inner.Elem().Int64(1) // inner.End() never called
	m.Field("b").Int64(2)
	return m.End()
}

// doubleWrite writes two scalars through the Encoder of one element or one
// entry. The result is one more value node than the count of the container.
type doubleWrite struct{ inSeq bool }

func (d doubleWrite) EncryptValue(enc Encoder) error {
	if d.inSeq {
		q := enc.Seq()
		e := q.Elem()
		e.Int64(1)
		e.Int64(2) // second value in the same element slot
		return q.End()
	}
	m := enc.Map()
	f := m.Field("a")
	f.Int64(1)
	f.Int64(2) // second value in the same entry slot
	return m.End()
}

// rootMiscount writes no value, or several values, at the root.
type rootMiscount struct{ writes int }

func (r rootMiscount) EncryptValue(enc Encoder) error {
	for i := 0; i < r.writes; i++ {
		enc.Int64(int64(i))
	}
	return nil
}

// unclosedRoot never calls End on the root container.
type unclosedRoot struct{}

func (unclosedRoot) EncryptValue(enc Encoder) error {
	enc.Seq().Elem().Int64(1) // End() never called
	return nil
}

// encodeCipherText requires exactly one value inside a Plain, as Marshal
// requires exactly one value at the root. Without the rule, a bad value
// would be written as bytes that UnmarshalCipherText refuses later, with
// only ErrMalformed.
func TestMarshalCipherTextRejectsPayloadMiscount(t *testing.T) {
	for _, v := range []any{
		Plain{V: rootMiscount{writes: 0}},
		Plain{V: rootMiscount{writes: 2}},
		Plain{V: unclosedRoot{}},
	} {
		if _, err := MarshalCipherText(testLeaves(), v); err == nil {
			t.Fatalf("malformed passthrough payload %#v must fail the encode", v)
		}
	}
}

// missingPassthroughPayload calls Passthrough for a sequence element and
// never writes the value. The mistake is a skipped value, in its passthrough
// form.
type missingPassthroughPayload struct{}

func (missingPassthroughPayload) EncryptValue(enc Encoder) error {
	s := enc.Seq()
	s.Elem().Passthrough() // marker written, payload omitted
	return s.End()
}

func TestEncoderPassthroughRequiresWrappedValue(t *testing.T) {
	_, err := Marshal(missingPassthroughPayload{})
	if err == nil {
		t.Fatal("passthrough without a wrapped value must fail at encode time")
	}
	if !strings.Contains(err.Error(), "element 0") {
		t.Fatalf("diagnostic %q should name the offending element", err)
	}
}

// collidingTag produces a duplicate key through reflection: the vc tag of
// one field is the name of another field. If the encoder accepted it, the
// failure would come from the ciphertext decoder, after the plaintext had
// crossed into the guest. That failure is an ErrMalformed that names neither
// the struct nor the key.
type collidingTag struct {
	Name  string
	Alias string `vc:"Name"`
}

// duplicateFieldKey produces the same duplicate key through an Encryptable.
type duplicateFieldKey struct{}

func (duplicateFieldKey) EncryptValue(enc Encoder) error {
	m := enc.Map()
	m.Field("a").Int64(1)
	m.Field("a").Int64(2)
	return m.End()
}

func TestEncoderRejectsDuplicateMapKeys(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
	}{
		{"struct tag collision", collidingTag{Name: "n", Alias: "m"}},
		{"encryptable double field", duplicateFieldKey{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Marshal(c.v)
			if err == nil {
				t.Fatal("a duplicate map key must fail at encode time")
			}
			if !strings.Contains(err.Error(), `"Name"`) && !strings.Contains(err.Error(), `"a"`) {
				t.Fatalf("diagnostic %q should name the colliding key", err)
			}
		})
	}
}

func TestEncoderCatchesSkippedValuesAtEncodeTime(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
		want string // text that the error must contain
	}{
		{"map middle", skipsValue{}, `key "a"`},
		{"map last", lastValueMissing{}, `key "b"`},
		{"seq middle", skipsValue{inSeq: true}, "element 0"},
		{"seq last", lastValueMissing{inSeq: true}, "element 1"},
		{"map unclosed nested container", unclosedNested{}, `key "a"`},
		{"seq unclosed nested container", unclosedNested{inSeq: true}, "element 0"},
		{"map double write", doubleWrite{}, `key "a"`},
		{"seq double write", doubleWrite{inSeq: true}, "element 0"},
		{"root zero values", rootMiscount{writes: 0}, "root"},
		{"root two values", rootMiscount{writes: 2}, "root"},
		{"root unclosed container", unclosedRoot{}, "root"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Marshal(c.v)
			if err == nil {
				t.Fatal("a contract violation must fail the encode")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("diagnostic %q does not name the offending slot (want substring %q)", err, c.want)
			}
		})
	}
}

// innerFailsOuterReports tests which error End returns. End returns the
// first error of the whole encode, not only an error from its own container.
// An outer End therefore reports a failure from inside another subtree.
type innerFailsOuterReports struct{}

func (innerFailsOuterReports) EncryptValue(enc Encoder) error {
	m := enc.Map()
	inner := m.Field("bad").Map()
	inner.Field("\xff").Int64(1) // invalid UTF-8 key: the first (and only) error
	_ = inner.End()
	m.Field("good").Int64(2)
	return m.End()
}

func TestEndReturnsFirstEncodeErrorNotContainerScoped(t *testing.T) {
	_, err := Marshal(innerFailsOuterReports{})
	if err == nil {
		t.Fatal("the inner container's error must surface from the outer End")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("outer End should carry the first encode error verbatim, got %q", err)
	}
}

// A caller's LeafSet encodes and decodes the caller's own leaf types. The
// ciphertext codec takes a LeafSet for this reason. A leaf must decode as
// the caller's type, never as the type of another LeafSet.
type otherSealed []byte

var otherLeaves = LeafSet{
	Classify: func(v any) (LeafKind, []byte, bool) {
		if s, ok := v.(otherSealed); ok {
			return LeafSingle, s, true
		}
		return 0, nil, false
	},
	Make: func(kind LeafKind, bytes []byte) any {
		if kind == LeafSingle {
			return otherSealed(bytes)
		}
		return nil
	},
}

func TestCipherTextLeafSetKeepsBindingTypesDistinct(t *testing.T) {
	ct := map[string]any{"email": otherSealed{9, 9, 9}}
	buf, err := MarshalCipherText(otherLeaves, ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(otherLeaves, buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}

	// Every LeafSet produces the same bytes, and only the Go types differ.
	// The same buffer therefore decodes to the test leaf types with
	// testLeaves. A LeafSet therefore changes only the Go types that are
	// built, never the encoding.
	asVC, err := UnmarshalCipherText(testLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText(testLeaves): %v", err)
	}
	want := map[string]any{"email": sealed{9, 9, 9}}
	if !reflect.DeepEqual(asVC, want) {
		t.Fatalf("got %#v, want %#v", asVC, want)
	}

	// A LeafSet treats a leaf type that it does not accept as plaintext that
	// is not marked. The encoder refuses the value, and does not write it as
	// passthrough.
	if _, err := MarshalCipherText(testLeaves(), ct); err == nil {
		t.Fatal("a leaf type outside the LeafSet must be rejected as bare plaintext")
	}
}

func TestCipherTextRejectsPartialLeafSet(t *testing.T) {
	for _, l := range []LeafSet{
		{},
		{Classify: otherLeaves.Classify},
		{Make: otherLeaves.Make},
	} {
		if _, err := MarshalCipherText(l, otherSealed{1}); err == nil {
			t.Fatal("a LeafSet missing Classify or Make must be rejected")
		}
		if _, err := UnmarshalCipherText(l, []byte{0x01, 1, 0, 0, 0, 0xAB}); err == nil {
			t.Fatal("a LeafSet missing Classify or Make must be rejected")
		}
	}
}

func TestCipherTextMakeMustMaterializeDecodedKind(t *testing.T) {
	// otherLeaves builds only a LeafSingle. Bytes that contain the
	// authenticated marker for an absent value must fail with an error that
	// names the cause. The bytes must never decode to a nil node. Such a
	// node would fail only later, in the caller's code.
	none := []byte{0x02, 0, 0, 0, 0}
	if _, err := UnmarshalCipherText(otherLeaves, none); err == nil {
		t.Fatal("a kind the LeafSet does not materialize must be rejected")
	}

	// The test LeafSet also refuses a kind that it does not list, and builds
	// no leaf for it. The function leafTag refuses the same kind when it
	// encodes.
	if got := testLeaves().Make(LeafKind(9), []byte{1}); got != nil {
		t.Fatalf("an unknown LeafKind must not materialize, got %#v", got)
	}
}

func TestMarshalCipherTextRejectsOutOfRangeLeafKind(t *testing.T) {
	// The encoder has the matching check. When Classify returns a kind that
	// the tag table does not have, the encoder refuses the leaf before it
	// writes any tag. A kind added later therefore cannot be encoded without
	// a tag of its own.
	badLeaves := LeafSet{
		Classify: func(v any) (LeafKind, []byte, bool) {
			if s, ok := v.(otherSealed); ok {
				return LeafKind(9), s, true
			}
			return 0, nil, false
		},
		Make: otherLeaves.Make,
	}
	if _, err := MarshalCipherText(badLeaves, otherSealed{1, 2, 3}); err == nil {
		t.Fatal("a Classify returning an out-of-range LeafKind must be rejected")
	}
}

func TestCipherTextRoundTripsAllLeafKinds(t *testing.T) {
	// The test uses every kind in the tag table, so it runs every case of
	// Classify and Make. Two cases that are swapped fail here, and not at
	// some later decrypt. An example is a Make that builds the empty-map
	// marker where the empty-sequence marker belongs.
	ct := map[string]any{
		"single":   sealed{9, 9, 9},
		"emptySeq": sealedEmptySeq{7},
		"emptyMap": sealedEmptyMap{8},
	}
	buf, err := MarshalCipherText(testLeaves(), ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(testLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

func TestLeafTagsHasNoUnwiredKinds(t *testing.T) {
	// A LeafKind constant that skips a value would leave a zero entry in
	// leafTags. Without the check for zero, leafTag would write the tag 0x00
	// with no error. The function leafKind would read that tag back. Go
	// would then encode and decode a tag that the Rust codec does not
	// define.
	//
	// Both functions refuse zero. The table must also have no zero entry.
	for kind, tag := range leafTags {
		if tag == 0 {
			t.Fatalf("LeafKind %d has no wire tag — a hole in leafTags", kind)
		}
	}
	if _, err := leafTag(LeafKind(len(leafTags))); err == nil {
		t.Fatal("a LeafKind past the end of the table must be refused")
	}
	if _, ok := leafKind(0); ok {
		t.Fatal("tag 0x00 is not a ciphertext tag and must not map to a kind")
	}
	if _, err := UnmarshalCipherText(testLeaves(), []byte{0x00, 0, 0, 0, 0}); err == nil {
		t.Fatal("a 0x00 tag must be rejected on the wire")
	}
}

func TestFramingTags(t *testing.T) {
	cases := []struct {
		value any
		wire  []byte
	}{
		{[]any{}, []byte{0xF0, 0, 0, 0, 0}},
		{Object{}, []byte{0xF1, 0, 0, 0, 0}},
		{Plain{V: nil}, []byte{0xF2, 0}},
	}
	for _, tc := range cases {
		got, err := Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.wire) {
			t.Fatalf("framing: got %x, want %x", got, tc.wire)
		}
	}
	for _, old := range []byte{0x10, 0x11, 0x12} {
		if _, err := Unmarshal([]byte{old}); err == nil {
			t.Fatalf("truncated scalar tag %x accepted", old)
		}
	}
}

// A signaling NaN must keep its bits. Widening it to float64 before it is
// encoded would set the quiet bit. The type namedFloat32 has no Encryptable
// method, so the encoder writes it by reflection.
type namedFloat32 float32

func TestFloat32SignalingNaNKeepsItsBits(t *testing.T) {
	for _, bits := range []uint32{0xff833030, 0x7fba3030, 0x7f800001} {
		wire := binary.LittleEndian.AppendUint32([]byte{tagFloat32}, bits)
		value, err := Unmarshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		f := value.(float32)
		for _, v := range []any{
			value, []any{value}, struct{ F float32 }{f},
			namedFloat32(f), []namedFloat32{namedFloat32(f)}, struct{ F namedFloat32 }{namedFloat32(f)},
		} {
			encoded, err := Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(encoded, wire) {
				t.Fatalf("%08x re-encoded as %x", bits, encoded)
			}
		}
	}
}
