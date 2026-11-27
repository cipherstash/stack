package vcffi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// marshalUnmarshal is the round trip every case below shares: encode v to
// transport bytes, decode back to the natives shape.
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
		{"int", 42, int64(42)},                 // int → Int64
		{"int8", int8(-5), int8(-5)},           // exact signed width
		{"int16", int16(-300), int16(-300)},    // exact signed width
		{"int32", int32(-9), int32(-9)},        // Int32, exact width
		{"int64", int64(-9), int64(-9)},        // Int64
		{"uint8", uint8(7), uint8(7)},          // exact unsigned width
		{"uint16", uint16(300), uint16(300)},   // exact unsigned width
		{"uint32", uint32(7), uint32(7)},       // UInt32, exact width
		{"uint", uint(7), uint64(7)},           // bare uint → UInt64 (no fit-check)
		{"uint64-small", uint64(7), uint64(7)}, // uint64 → UInt64
		{"uint64-max", uint64(math.MaxUint64), uint64(math.MaxUint64)},
		{"float32", float32(1.5), float32(1.5)}, // Float32, exact width
		{"float", 1.5, 1.5},                     // float64 → Float64
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
	want := vcvalue.Object{
		{Key: "name", Value: "x"},
		{Key: "Nested", Value: vcvalue.Object{{Key: "a", Value: int64(1)}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReflectMapSortsKeys(t *testing.T) {
	// Map iteration is randomized; the encoder must sort keys so the
	// structure is deterministic. Decode preserves that sorted order.
	got := marshalUnmarshal(t, map[string]int64{"c": 3, "a": 1, "b": 2})
	want := vcvalue.Object{
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

// point uses the Encryptable extension point.
type point struct{ X, Y int64 }

func (p point) EncryptValue(enc Encoder) error {
	m := enc.Map()
	m.Field("x").Int64(p.X)
	m.Field("y").Int64(p.Y)
	return m.End()
}

func TestEncryptableImpl(t *testing.T) {
	got := marshalUnmarshal(t, point{X: 1, Y: 2})
	want := vcvalue.Object{{Key: "x", Value: int64(1)}, {Key: "y", Value: int64(2)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// TestEncryptableNested confirms an Encryptable is honored when reached
// through reflection (as a struct field), not only at the top level.
func TestEncryptableNested(t *testing.T) {
	type shape struct {
		Origin point
	}
	got := marshalUnmarshal(t, shape{Origin: point{X: 3, Y: 4}})
	want := vcvalue.Object{
		{Key: "Origin", Value: vcvalue.Object{
			{Key: "x", Value: int64(3)},
			{Key: "y", Value: int64(4)},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestEncoderChannels(t *testing.T) {
	// Drive the raw Encoder channels directly, including a nested Seq.
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
	s.Elem().UInt32(math.MaxUint32)
	s.Elem().UInt64(math.MaxUint64)
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
	// Trailing bytes after a complete value.
	if _, err := Unmarshal([]byte{0x00, 0x00}); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
}

// TestPlainPassthroughRoundTrip: the reflection opt-in marker Plain seals a
// value as passthrough, and it decodes back as Plain{V:...} — the marking
// round-trips so a caller can tell the field travelled in the clear.
func TestPlainPassthroughRoundTrip(t *testing.T) {
	got := marshalUnmarshal(t, map[string]any{
		"id":    vcvalue.Plain{V: int64(42)},
		"email": "ada@example.com",
	})
	want := vcvalue.Object{
		{Key: "email", Value: "ada@example.com"},
		{Key: "id", Value: vcvalue.Plain{V: int64(42)}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// A Plain wrapping a whole subtree makes the entire subtree passthrough.
func TestPlainPassthroughSubtree(t *testing.T) {
	got := marshalUnmarshal(t, vcvalue.Plain{V: []any{int64(1), "two", true}})
	want := vcvalue.Plain{V: []any{int64(1), "two", true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// The raw Encoder.Passthrough() channel, at root/seq/map positions.
type passthroughBuilder struct{}

func (passthroughBuilder) EncryptValue(enc Encoder) error {
	s := enc.Seq()
	s.Elem().Passthrough().Int64(7) // passthrough sequence element
	s.Elem().String("sealed")
	return s.End()
}

func TestEncoderPassthroughChannel(t *testing.T) {
	got := marshalUnmarshal(t, passthroughBuilder{})
	want := []any{vcvalue.Plain{V: int64(7)}, "sealed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestUnmarshalRejectsTruncatedPassthrough(t *testing.T) {
	// A passthrough marker (0xF2) with no value node behind it.
	if _, err := Unmarshal([]byte{0xF2}); err == nil {
		t.Fatal("truncated passthrough node must be rejected")
	}
}

func TestUnmarshalRejectsPassthroughDepthBomb(t *testing.T) {
	// Nesting exclusively through passthrough markers must hit the depth bound.
	bytes := make([]byte, 0, 200)
	for range 130 { // > maxDepth (128)
		bytes = append(bytes, 0xF2)
	}
	bytes = append(bytes, 0x00) // NULL
	if _, err := Unmarshal(bytes); err == nil {
		t.Fatal("over-deep passthrough nesting must be rejected")
	}
}

// A passthrough ciphertext node carries its readable value across the
// transport and back, marked Plain so it cannot be mistaken for a
// ciphertext map or sequence on the way back in.
func TestCipherTextPassthroughTransportRoundTrip(t *testing.T) {
	ct := map[string]any{
		"id":    vcvalue.Plain{V: int64(42)},
		"email": vcvalue.Sealed{9, 9, 9},
	}
	buf, err := MarshalCipherText(VCValueLeaves(), ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(VCValueLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

func TestCipherTextTransportRoundTrip(t *testing.T) {
	ct := map[string]any{
		"a": vcvalue.Sealed{9, 9, 9},
		"b": []any{vcvalue.Sealed{1}, vcvalue.SealedEmptySeq{2}},
	}
	buf, err := MarshalCipherText(VCValueLeaves(), ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(VCValueLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

// A bare plaintext value in ciphertext position is rejected: passthrough must
// be explicit (Plain), so nothing travels unencrypted by accident.
func TestCipherTextRejectsBarePlaintext(t *testing.T) {
	if _, err := MarshalCipherText(VCValueLeaves(), map[string]any{"x": "oops"}); err == nil {
		t.Fatal("bare plaintext in ciphertext position must be rejected")
	}
	if _, err := MarshalCipherText(VCValueLeaves(), []byte{1, 2, 3}); err == nil {
		t.Fatal("bare []byte must be rejected (use Sealed or Plain)")
	}
}

// A struct with zero exported fields (time.Time is the canonical case) must
// be rejected, not silently sealed as an empty map that destroys the payload.
func TestMarshalRejectsZeroExportedFieldStruct(t *testing.T) {
	type opaque struct {
		hidden int //nolint:unused // unexported on purpose
	}
	if _, err := Marshal(opaque{hidden: 1}); err == nil {
		t.Fatal("struct with no exported fields must be rejected")
	}
	// An all-vc:"-" struct asked for the empty encoding explicitly and stays
	// allowed, as does the empty struct.
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

// Object (the decode result for maps) must re-encode with object framing so
// a decrypt-then-re-encrypt flow preserves the record's structure — both at
// the root and nested inside other values.
func TestObjectReencodesWithObjectFraming(t *testing.T) {
	o := vcvalue.Object{
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

// A Plain-wrapped Object inside a ciphertext must survive the passthrough
// round trip shape-intact (PR review P1).
func TestCipherTextPassthroughObjectRoundTrip(t *testing.T) {
	o := vcvalue.Object{{Key: "id", Value: int64(42)}}
	buf, err := MarshalCipherText(VCValueLeaves(), vcvalue.Plain{V: o})
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(VCValueLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, vcvalue.Plain{V: o}) {
		t.Fatalf("got %#v, want Plain{V: %#v}", got, o)
	}
}

// [N]byte must take the same single-Bytes-leaf path as []byte — element-wise
// encoding would produce a ciphertext shape no other producer emits.
func TestByteArrayEncodesAsBytes(t *testing.T) {
	got := marshalUnmarshal(t, [4]byte{1, 2, 3, 4})
	if !reflect.DeepEqual(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("got %#v, want []byte{1,2,3,4}", got)
	}
	type hashed struct {
		Hash [4]byte
	}
	got = marshalUnmarshal(t, hashed{Hash: [4]byte{9, 8, 7, 6}})
	want := vcvalue.Object{{Key: "Hash", Value: []byte{9, 8, 7, 6}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// nilEncryptable panics if EncryptValue is called through a nil receiver —
// the behaviour typed-nil detection must prevent.
type nilEncryptable struct{ n int }

func (e *nilEncryptable) EncryptValue(enc Encoder) error {
	enc.Int64(int64(e.n)) // dereferences e
	return nil
}

// A typed nil pointer satisfying Encryptable must encode as Null, not invoke
// the method on a nil receiver (PR review P2).
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

// A pointer cycle must fail with an error, not recurse to stack overflow
// (PR review P2).
func TestMarshalRejectsPointerCycle(t *testing.T) {
	var x any
	x = &x
	if _, err := Marshal(x); err == nil {
		t.Fatal("pointer cycle must be rejected")
	}
}

// MarshalCipherText must reject a passthrough whose payload sits beyond the
// depth budget instead of emitting bytes UnmarshalCipherText is guaranteed
// to reject (PR review P2).
func TestMarshalCipherTextRejectsPassthroughBeyondDepthBudget(t *testing.T) {
	// 129 nested []any push the Plain payload past maxDepth (128).
	var deep any = vcvalue.Plain{V: int64(1)}
	for range 129 {
		deep = []any{deep}
	}
	if _, err := MarshalCipherText(VCValueLeaves(), deep); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("over-deep passthrough must be rejected with ErrTooDeep at encode time, got %v", err)
	}

	// One level shallower still round-trips — the bound is exact.
	var ok any = vcvalue.Plain{V: int64(1)}
	for range 127 {
		ok = []any{ok}
	}
	buf, err := MarshalCipherText(VCValueLeaves(), ok)
	if err != nil {
		t.Fatalf("MarshalCipherText at the bound: %v", err)
	}
	if _, err := UnmarshalCipherText(VCValueLeaves(), buf); err != nil {
		t.Fatalf("UnmarshalCipherText at the bound: %v", err)
	}
}

// --- Malformed-input coverage for the two decoders (PR #257 review gaps).
// Raw transport bytes are hand-built here because no Go encoder produces
// these shapes — that unreachability is exactly why the branches were
// untested.

func u32le(n int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b
}

// ctEntry frames one ciphertext map entry: key chunk + a 1-byte ctSingle leaf.
func ctEntry(key string) []byte {
	e := append(u32le(len(key)), key...)
	e = append(e, 0x01) // ctSingle
	e = append(e, u32le(1)...)
	return append(e, 0xAB)
}

// decodeCipherText rejects a duplicate map key — a branch only reachable
// from hand-crafted or cross-language transport bytes (a Go map cannot
// produce duplicates).
func TestUnmarshalCipherTextRejectsDuplicateKey(t *testing.T) {
	dup := []byte{0x04} // ctMap
	dup = append(dup, u32le(2)...)
	dup = append(dup, ctEntry("a")...)
	dup = append(dup, ctEntry("a")...)
	if _, err := UnmarshalCipherText(VCValueLeaves(), dup); err == nil {
		t.Fatal("duplicate ciphertext map key must be rejected")
	}

	// Positive control: the same framing with distinct keys decodes.
	ok := []byte{0x04}
	ok = append(ok, u32le(2)...)
	ok = append(ok, ctEntry("a")...)
	ok = append(ok, ctEntry("b")...)
	if _, err := UnmarshalCipherText(VCValueLeaves(), ok); err != nil {
		t.Fatalf("distinct keys should decode: %v", err)
	}
}

// Unmarshal's recursion bound and hostile-count guard on the array/object
// routes — the Rust codec tests all three; only the passthrough depth bomb
// was covered on the Go side.
func TestUnmarshalRejectsArrayAndObjectBombs(t *testing.T) {
	// Depth bomb: 130 nested single-element arrays (> maxDepth 128).
	var deep []byte
	for range 130 {
		deep = append(deep, 0xF0) // tagArray
		deep = append(deep, u32le(1)...)
	}
	deep = append(deep, 0x00) // tagNull
	if _, err := Unmarshal(deep); err == nil {
		t.Fatal("array depth bomb must be rejected")
	}

	// Object nesting: 130 nested one-entry objects.
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

	// Hostile count: an array claiming max-u32 items with no bytes behind it.
	if _, err := Unmarshal([]byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("hostile array count must be rejected")
	}
}

// UnmarshalCipherText's own recursion bound, hostile-count guard, and
// trailing-byte rejection — a separate recursion from the value decoder,
// previously untested.
func TestUnmarshalCipherTextRejectsMalformed(t *testing.T) {
	// Depth bomb: 130 nested one-element ctSeq.
	var deep []byte
	for range 130 {
		deep = append(deep, 0x03) // ctSeq
		deep = append(deep, u32le(1)...)
	}
	deep = append(deep, ctEntry("")[4:]...) // a bare ctSingle leaf
	if _, err := UnmarshalCipherText(VCValueLeaves(), deep); err == nil {
		t.Fatal("ciphertext depth bomb must be rejected")
	}

	// Hostile count.
	if _, err := UnmarshalCipherText(VCValueLeaves(), []byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("hostile ciphertext count must be rejected")
	}

	// Trailing bytes after a complete node.
	leaf := append([]byte{0x01}, u32le(1)...)
	leaf = append(leaf, 0xAB, 0xFF) // one extra byte
	if _, err := UnmarshalCipherText(VCValueLeaves(), leaf); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}

	// Unknown tag.
	if _, err := UnmarshalCipherText(VCValueLeaves(), []byte{0x7F}); err == nil {
		t.Fatal("unknown ciphertext tag must be rejected")
	}
}

// The encodeReflect default arm: kinds with no encoding (chan/func/complex)
// error instead of panicking or emitting garbage.
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

// encodeMap rejects non-string map keys — the transport frames keys as
// UTF-8 chunks, so there is nothing sound to write for other key types.
func TestMarshalRejectsNonStringMapKey(t *testing.T) {
	if _, err := Marshal(map[int]string{1: "a"}); err == nil {
		t.Fatal("map with non-string keys must be rejected")
	}
}

// The encode-side recursion guard: an over-deep Go value fails the encode.
// The decode side has depth-bomb coverage; this drives the same bound from
// the writing end.
func TestMarshalRejectsDepthBomb(t *testing.T) {
	var v any = int64(0)
	for range 130 { // > maxDepth (128)
		v = []any{v}
	}
	if _, err := Marshal(v); err == nil {
		t.Fatal("over-deep value must be rejected at encode time")
	}
}

// A duplicate object key in the wire bytes must be rejected exactly as the
// ciphertext decoder rejects a duplicate ctMap key: an Object carrying
// duplicates cannot survive re-encoding through a Go map without silently
// dropping an entry. Only hand-built transport bytes can reach this branch —
// the encoder sorts unique map keys.
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

	// Positive control: the same shape with distinct keys decodes.
	var ok []byte
	ok = append(ok, 0xF1, 2, 0, 0, 0)
	ok = append(ok, 1, 0, 0, 0, 'a', 0x00)
	ok = append(ok, 1, 0, 0, 0, 'b', 0x00)
	if _, err := Unmarshal(ok); err != nil {
		t.Fatalf("distinct keys must decode: %v", err)
	}
}

// skipsValue writes a key (or claims an element) and never writes the value —
// the contract violation Field/Elem must now catch at encode time, where it
// previously surfaced only as an opaque ErrMalformed at decode.
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

// lastValueMissing exercises the End-side check: the final entry's value is
// the one skipped, so no later Field/Elem call can catch it.
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

// unclosedNested completes a terminal *inside* a nested container but never
// Ends the container — the slot itself is incomplete even though a descendant
// value finished, so a per-slot (not global) completion check is required.
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

// doubleWrite pushes two terminals through one element/entry Encoder,
// producing an extra value node the container's count doesn't account for.
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

// rootMiscount writes zero or several values at the root slot.
type rootMiscount struct{ writes int }

func (r rootMiscount) EncryptValue(enc Encoder) error {
	for i := 0; i < r.writes; i++ {
		enc.Int64(int64(i))
	}
	return nil
}

// unclosedRoot leaves the root container un-Ended.
type unclosedRoot struct{}

func (unclosedRoot) EncryptValue(enc Encoder) error {
	enc.Seq().Elem().Int64(1) // End() never called
	return nil
}

// The passthrough payload path in encodeCipherText applies the same
// exactly-one rule as Marshal's root slot; without this, a malformed payload
// would emit wire bytes that UnmarshalCipherText only rejects later as an
// opaque ErrMalformed.
func TestMarshalCipherTextRejectsPayloadMiscount(t *testing.T) {
	for _, v := range []any{
		vcvalue.Plain{V: rootMiscount{writes: 0}},
		vcvalue.Plain{V: rootMiscount{writes: 2}},
		vcvalue.Plain{V: unclosedRoot{}},
	} {
		if _, err := MarshalCipherText(VCValueLeaves(), v); err == nil {
			t.Fatalf("malformed passthrough payload %#v must fail the encode", v)
		}
	}
}

// missingPassthroughPayload writes a Passthrough marker into a sequence slot
// but never the wrapped value — the passthrough-specific skipped-value case.
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

// collidingTag is the reflection route to a duplicate wire key: a vc tag
// resolving to another field's effective name. Without encode-time rejection
// this marshals happily and only fails inside the ciphertext decoder — after
// the plaintext crossed the FFI boundary — as an ErrMalformed that names
// neither the struct nor the key.
type collidingTag struct {
	Name  string
	Alias string `vc:"Name"`
}

// duplicateFieldKey is the Encryptable route to the same collision.
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
		want string // substring the diagnostic must carry
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

// innerFailsOuterReports pins the End() error contract: End returns the
// first error of the whole encode, not one scoped to its own container, so
// an outer End reports a failure that happened inside a sibling subtree.
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

// A binding-specific LeafSet round-trips its own distinct leaf types — the
// reason the ciphertext codec is parameterised at all: a stack-encrypt leaf
// must come back as a stack-encrypt type, never as vcvalue.Sealed.
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

	// The wire bytes are identical across LeafSets — only the Go types
	// differ — so the same buffer decodes to vcvalue types under
	// VCValueLeaves. This pins that a LeafSet changes materialization, not
	// the encoding.
	asVC, err := UnmarshalCipherText(VCValueLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText(VCValueLeaves): %v", err)
	}
	want := map[string]any{"email": vcvalue.Sealed{9, 9, 9}}
	if !reflect.DeepEqual(asVC, want) {
		t.Fatalf("got %#v, want %#v", asVC, want)
	}

	// And a foreign leaf type is a bare plaintext to a LeafSet that does not
	// claim it — rejected, not silently passed through.
	if _, err := MarshalCipherText(VCValueLeaves(), ct); err == nil {
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
	// otherLeaves materializes only LeafSingle. Wire bytes carrying the
	// authenticated absent marker must fail attributably — never decode to a
	// nil node the caller only trips over later.
	none := []byte{0x02, 0, 0, 0, 0}
	if _, err := UnmarshalCipherText(otherLeaves, none); err == nil {
		t.Fatal("a kind the LeafSet does not materialize must be rejected")
	}

	// The vcvalue set likewise rejects an unlisted kind instead of minting a
	// Sealed for it — mirroring leafTag's refusal on the encode side.
	if got := VCValueLeaves().Make(LeafKind(9), []byte{1}); got != nil {
		t.Fatalf("an unknown LeafKind must not materialize, got %#v", got)
	}
}

func TestMarshalCipherTextRejectsOutOfRangeLeafKind(t *testing.T) {
	// The encode-side half of the pair above: a Classify that claims a leaf
	// under a kind outside the wire table is refused before any tag is
	// emitted, so a future fifth kind can never reach the wire unnamed.
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
	// Every kind in the wire table, so no Classify or Make arm goes
	// unexercised: a swapped arm (an empty-map marker materialized where an
	// empty-seq belongs) fails here rather than at some later decrypt.
	ct := map[string]any{
		"single":   vcvalue.Sealed{9, 9, 9},
		"emptySeq": vcvalue.SealedEmptySeq{7},
		"emptyMap": vcvalue.SealedEmptyMap{8},
	}
	buf, err := MarshalCipherText(VCValueLeaves(), ct)
	if err != nil {
		t.Fatalf("MarshalCipherText: %v", err)
	}
	got, err := UnmarshalCipherText(VCValueLeaves(), buf)
	if err != nil {
		t.Fatalf("UnmarshalCipherText: %v", err)
	}
	if !reflect.DeepEqual(got, ct) {
		t.Fatalf("got %#v, want %#v", got, ct)
	}
}

func TestLeafTagsHasNoUnwiredKinds(t *testing.T) {
	// A LeafKind constant that skips a value would leave a zero hole in
	// leafTags. Without the zero guard, leafTag would emit tag 0x00 with no
	// error and leafKind would map it straight back — a clean round trip
	// inside Go under a tag the Rust codec does not define. Both directions
	// refuse zero, and the table itself must have no holes to refuse.
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
	if _, err := UnmarshalCipherText(VCValueLeaves(), []byte{0x00, 0, 0, 0, 0}); err == nil {
		t.Fatal("a 0x00 tag must be rejected on the wire")
	}
}

func TestFramingTags(t *testing.T) {
	cases := []struct {
		value any
		wire  []byte
	}{
		{[]any{}, []byte{0xF0, 0, 0, 0, 0}},
		{vcvalue.Object{}, []byte{0xF1, 0, 0, 0, 0}},
		{vcvalue.Plain{V: nil}, []byte{0xF2, 0}},
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

// A signaling NaN must keep its bits: widening it to float64 on the way to
// the encoder would set the quiet bit (found by FuzzUnmarshal).
// namedFloat32 has no Encryptable method, so it reaches the reflect path.
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
