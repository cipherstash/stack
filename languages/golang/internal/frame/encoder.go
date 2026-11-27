package vcffi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Encryptable is the extension point for user types: a type implements it to
// control how it is sealed, the way a Rust type implements `Encrypt`. Because
// Go has no orphan impls, this interface (rather than reflection) is how a
// type opts into a bespoke encoding. Encode and Marshal consult it before
// falling back to reflection.
type Encryptable interface {
	// EncryptValue records this value into enc. Implementations write
	// exactly one value: one terminal channel (String, Int, …) or one
	// container (Seq, Map). Returning an error aborts the whole encode.
	EncryptValue(enc Encoder) error
}

// FixedWidth is the Go side of Rust's `Encrypt::FIXED`: an Encryptable whose
// EncryptValue always writes one value of one fixed-width type (a money type
// that writes its cents with Int64, say). A nil pointer to such a type is
// written as a typed null of that type, so a sealed absence is as long as a
// sealed value. A nil pointer to an Encryptable that does not implement it
// is the plain null, since its encoding is its own.
//
// FixedType is called once per type, on a pointer to a zero value, so it
// must answer from the type alone. A type that returns an invalid FixedType
// fails the encode with vcvalue.ErrInvalidFixedType rather than write the
// plain null in its place.
type FixedWidth interface {
	Encryptable
	FixedType() vcvalue.FixedType
}

// encState is the buffer and first-error shared by an Encoder and every
// sub-encoder it hands out. Errors accumulate: once one is recorded, further
// channel calls are no-ops, so consumer code can chain writes without
// checking after every call and still surface the first failure from
// End/Marshal.
type encState struct {
	buf []byte
	err error
}

func (s *encState) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// Encoder records a single value in transport form. It mirrors the Rust
// Cipher channels — it is a recorder that writes the transport bytes, not a
// live cipher handle. Exactly one channel must be used per Encoder: a
// terminal (Null, Undefined, Bool, Int32, Int64, UInt32, UInt64, Float32,
// Float64, String, Bytes) or a container (Seq, Map).
//
// Encoder is passed and stored by value; all instances handed out for one
// encode share the same underlying buffer and first-error via a pointer, so
// copying an Encoder is cheap and safe. The zero Encoder is not usable and
// its methods panic: usable Encoders are only the one handed to
// [Encryptable.EncryptValue] and those returned by Passthrough, Elem and
// Field.
type Encoder struct {
	st    *encState
	depth int
	// done points at the completion counter for the slot this Encoder writes
	// into (a container's current element/entry, or the root). Terminals and
	// container Ends increment it; the slot's owner then verifies exactly one
	// completion. This is per-slot on purpose: a global counter would let a
	// completed *descendant* (e.g. a terminal inside an un-Ended nested
	// container) stand in for the slot's own value, shifting the wire and
	// surfacing only as an opaque ErrMalformed at decode.
	done *int
}

func (e Encoder) push(b ...byte) {
	e.st.buf = append(e.st.buf, b...)
}

// complete records that this Encoder's slot received one full value.
func (e Encoder) complete() {
	if e.done != nil {
		*e.done++
	}
}

// Null records the cross-language null (Go nil, JS null, Python None).
func (e Encoder) Null() {
	if e.st.err == nil {
		e.push(tagNull)
		e.complete()
	}
}

// Undefined records JavaScript's undefined. Go has no analog, so Go code
// rarely writes it; the channel exists so a value round-tripped from JS can
// be re-encoded. On decode, Undefined collapses to nil like Null.
func (e Encoder) Undefined() {
	if e.st.err == nil {
		e.push(tagUndefined)
		e.complete()
	}
}

// Bool records a boolean.
func (e Encoder) Bool(b bool) {
	if e.st.err != nil {
		return
	}
	if b {
		e.push(tagTrue)
	} else {
		e.push(tagFalse)
	}
	e.complete()
}

// Float64 records an IEEE-754 double. Distinct from the integer channels: it
// round-trips as a 64-bit float in every language. Round-trips by raw bit
// pattern, so NaN payloads and -0.0 survive.
func (e Encoder) Float64(f float64) {
	if e.st.err != nil {
		return
	}
	e.push(tagFloat64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, math.Float64bits(f))
	e.complete()
}

// Float32 records an IEEE-754 single. For schema fidelity with float4 at the
// EQL layer; round-trips by raw bit pattern.
func (e Encoder) Float32(f float32) {
	if e.st.err != nil {
		return
	}
	e.push(tagFloat32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, math.Float32bits(f))
	e.complete()
}

// Int32 records a signed 32-bit integer. For schema fidelity with int4 at
// the EQL layer; kept distinct from Int64.
func (e Encoder) Int32(i int32) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, uint32(i))
	e.complete()
}

// Int64 records a signed 64-bit integer. Kept distinct from Float64 so
// integer-typed languages round-trip integers as integers.
func (e Encoder) Int64(i int64) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, uint64(i))
	e.complete()
}

// UInt32 records an unsigned 32-bit integer. For schema fidelity with the
// EQL layer.
func (e Encoder) UInt32(u uint32) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, u)
	e.complete()
}

// UInt64 records an unsigned 64-bit integer without changing its width.
func (e Encoder) UInt64(u uint64) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, u)
	e.complete()
}

// String records a UTF-8 string. Invalid UTF-8 fails the encode.
func (e Encoder) String(s string) {
	if e.st.err != nil {
		return
	}
	if !utf8.ValidString(s) {
		e.st.fail(errors.New("vcffi: string is not valid UTF-8"))
		return
	}
	e.push(tagString)
	if buf, err := appendChunk(e.st.buf, []byte(s)); err != nil {
		e.st.fail(err)
	} else {
		e.st.buf = buf
		e.complete()
	}
}

// Bytes records raw binary data.
func (e Encoder) Bytes(b []byte) {
	if e.st.err != nil {
		return
	}
	e.push(tagBytes)
	if buf, err := appendChunk(e.st.buf, b); err != nil {
		e.st.fail(err)
	} else {
		e.st.buf = buf
		e.complete()
	}
}

// Passthrough marks the next value as passthrough (unencrypted,
// unauthenticated) and returns an Encoder for it — the same channel set, so
// the wrapped value is written exactly as any other:
//
//	m.Field("id").Passthrough().Int64(42)   // a passthrough map entry
//	enc.Passthrough().String("v")           // a passthrough root value
//	s.Elem().Passthrough().Bool(true)       // a passthrough sequence element
//
// Write exactly one value (terminal or container) through the returned
// Encoder. Non-sensitive data only — the wrapped value is not sealed.
func (e Encoder) Passthrough() Encoder {
	if e.st.err == nil {
		if e.depth+1 > maxDepth {
			e.st.fail(ErrTooDeep)
		} else {
			e.push(tagPassthrough)
		}
	}
	// The passthrough marker and its wrapped value form ONE value in this
	// Encoder's slot, so the wrapped value completes the same counter.
	return Encoder{st: e.st, depth: e.depth + 1, done: e.done}
}

// Seq begins a sequence. Call Elem once per element and End when done.
func (e Encoder) Seq() *SeqEncoder {
	s := &SeqEncoder{st: e.st, depth: e.depth + 1, done: e.done}
	if e.st.err != nil {
		return s
	}
	if e.depth+1 > maxDepth {
		e.st.fail(ErrTooDeep)
		return s
	}
	e.push(tagArray)
	s.lenOff = len(e.st.buf)
	e.push(0, 0, 0, 0) // length back-patched by End
	return s
}

// Map begins a string-keyed map. Call Field once per entry and End when
// done. Keys preserve insertion order and are UTF-8 validated.
func (e Encoder) Map() *MapEncoder {
	m := &MapEncoder{st: e.st, depth: e.depth + 1, done: e.done}
	if e.st.err != nil {
		return m
	}
	if e.depth+1 > maxDepth {
		e.st.fail(ErrTooDeep)
		return m
	}
	e.push(tagObject)
	m.lenOff = len(e.st.buf)
	e.push(0, 0, 0, 0) // length back-patched by End
	return m
}

// SeqEncoder records the elements of a sequence. The element count is
// back-patched into the reserved length slot at End.
type SeqEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
	// done is the enclosing slot's completion counter (see Encoder.done);
	// End increments it — the sequence is one value in its parent's slot.
	done *int
	// childDone counts completions of this sequence's own element slots.
	// Elem and End verify childDone == count, so a skipped element, an
	// un-Ended nested container, or a doubly-written element fails here at
	// encode time instead of as ErrMalformed at decode.
	childDone int
}

// checkPrev verifies the previous element slot completed exactly once.
func (s *SeqEncoder) checkPrev() {
	if s.childDone > s.count {
		s.st.fail(fmt.Errorf("vcffi: more than one value was written for sequence element %d", s.count-1))
	} else if s.count > 0 && s.childDone < s.count {
		s.st.fail(fmt.Errorf("vcffi: sequence element %d was never completed", s.count-1))
	}
}

// Elem returns an Encoder for the next element. Write the element fully
// (one channel, containers Ended) before calling Elem again.
func (s *SeqEncoder) Elem() Encoder {
	if s.st.err == nil {
		s.checkPrev()
		if s.st.err == nil {
			s.count++
		}
	}
	return Encoder{st: s.st, depth: s.depth, done: &s.childDone}
}

// End finalizes the sequence, writing its element count.
//
// Error contract (deliberate, frozen): End returns the first error recorded
// anywhere in the whole encode so far — not one scoped to this sequence. A
// nested container's End can therefore surface an error caused elsewhere in
// the tree. Errors are sticky (later channel calls no-op), so an
// EncryptValue implementation may chain writes without checking and return
// the outermost End; inspecting intermediate errors for *which* slot failed
// is not part of the contract — the error text names the slot instead.
func (s *SeqEncoder) End() error {
	if s.st.err == nil {
		s.checkPrev()
	}
	err := patchLen(s.st, s.lenOff, s.count)
	if err == nil {
		// The sequence itself is one completed value in the enclosing slot.
		if s.done != nil {
			*s.done++
		}
	}
	return err
}

// MapEncoder records the entries of a map. The entry count is back-patched
// into the reserved length slot at End.
type MapEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
	// done is the enclosing slot's completion counter (see Encoder.done);
	// End increments it — the map is one value in its parent's slot.
	done *int
	// childDone mirrors SeqEncoder.childDone: completions of this map's own
	// entry slots. Field and End verify childDone == count, so a key whose
	// value was skipped, left as an un-Ended container, or written twice
	// fails at encode time — otherwise the wire shifts and the next key
	// parses as the missing value, surfacing only as ErrMalformed at decode.
	childDone int
	// lastKey is the most recent Field key, kept so contract violations name
	// the key whose value slot misbehaved.
	lastKey string
	// seen rejects duplicate keys at encode time. Reflection over a Go map
	// cannot produce duplicates, but encodeStruct can (a vc tag colliding
	// with another field's effective name) and a hand-written Encryptable
	// can; without this check the collision only surfaces after the
	// plaintext has crossed the FFI boundary, as the ciphertext decoder's
	// opaque ErrMalformed naming neither the struct nor the key.
	seen map[string]struct{}
}

// checkPrev verifies the previous entry's value slot completed exactly once.
func (m *MapEncoder) checkPrev() {
	if m.childDone > m.count {
		m.st.fail(fmt.Errorf("vcffi: more than one value was written for key %q", m.lastKey))
	} else if m.count > 0 && m.childDone < m.count {
		m.st.fail(fmt.Errorf("vcffi: value for key %q was never completed", m.lastKey))
	}
}

// Field writes an entry key and returns an Encoder for its value. Write the
// value fully (one channel, containers Ended) before calling Field again.
// Keys are UTF-8 validated; insertion order is preserved on the wire.
func (m *MapEncoder) Field(key string) Encoder {
	if m.st.err == nil {
		m.checkPrev()
	}
	if m.st.err == nil {
		if !utf8.ValidString(key) {
			m.st.fail(errors.New("vcffi: object key is not valid UTF-8"))
		} else if _, dup := m.seen[key]; dup {
			m.st.fail(fmt.Errorf("vcffi: duplicate key %q in map encoding", key))
		} else if buf, err := appendChunk(m.st.buf, []byte(key)); err != nil {
			m.st.fail(err)
		} else {
			m.st.buf = buf
			if m.seen == nil {
				m.seen = make(map[string]struct{})
			}
			m.seen[key] = struct{}{}
			m.lastKey = key
			m.count++
		}
	}
	return Encoder{st: m.st, depth: m.depth, done: &m.childDone}
}

// End finalizes the map, writing its entry count. Same error contract as
// SeqEncoder.End: the first error of the whole encode, not one scoped to
// this map.
func (m *MapEncoder) End() error {
	if m.st.err == nil {
		m.checkPrev()
	}
	err := patchLen(m.st, m.lenOff, m.count)
	if err == nil {
		// The map itself is one completed value in the enclosing slot.
		if m.done != nil {
			*m.done++
		}
	}
	return err
}

func patchLen(st *encState, off, count int) error {
	if st.err != nil {
		return st.err
	}
	if count < 0 || uint64(count) > maxUint32 {
		st.fail(fmt.Errorf("vcffi: item count %d out of range", count))
		return st.err
	}
	binary.LittleEndian.PutUint32(st.buf[off:off+4], uint32(count))
	return nil
}

// Marshal encodes v into the value transport form a wasm guest expects: the
// encode counterpart of [Unmarshal], and the path a binding's Encrypt takes.
func Marshal(v any) ([]byte, error) {
	st := &encState{}
	var root int
	if err := Encode(Encoder{st: st, done: &root}, v); err != nil {
		return nil, err
	}
	// The reflection paths always write exactly one value; only an
	// Encryptable can leave the root empty (or an un-Ended container) or
	// write more than once.
	if root != 1 {
		return nil, fmt.Errorf("vcffi: encode must complete exactly one root value, completed %d", root)
	}
	return st.buf, nil
}

// Encode records v into enc following encoding/json-style rules, but
// consulting the Encryptable interface first:
//
//   - a value implementing Encryptable uses its EncryptValue;
//   - nil                        → Null;
//   - bool                       → Bool;
//   - int8/int16/int32           → Int8/Int16/Int32;
//   - int/int64                  → Int64;
//   - uint8/uint16/uint32        → UInt8/UInt16/UInt32;
//   - uint/uint64/uintptr        → UInt64;
//   - float32                    → Float32;
//   - float64                    → Float64;
//   - string                     → String;
//   - []byte                     → Bytes;
//   - slices/arrays              → Seq;
//   - map[string]T               → Map, keys SORTED for determinism;
//   - structs                    → Map by field name, honoring `vc:"name"`
//     tags (`vc:"-"` skips a field; options after a comma, such as the
//     storage profile's `,default`, do not change the name), in
//     declaration order;
//   - pointers                   → dereferenced; a nil pointer → a typed
//     null if its element type is fixed width (see [fixedTypeOf]), Null
//     otherwise;
//   - vcvalue.TypedNull          → a typed null of its type.
//
// Map keys are sorted because Go map iteration order is randomized;
// sorting makes the encrypted structure deterministic. Struct fields keep
// declaration order.
//
// Encode returns the first error recorded while writing enc, so it composes:
// an Encryptable can delegate a sub-value with vcffi.Encode(m.Field(k), x).
func Encode(enc Encoder, v any) error {
	encodeAny(enc, v)
	return enc.st.err
}

func encodeAny(enc Encoder, v any) {
	if enc.st.err != nil {
		return
	}
	if v == nil {
		enc.Null()
		return
	}
	if interceptMarkers(enc, v) {
		return
	}
	if b, ok := v.([]byte); ok {
		enc.Bytes(b)
		return
	}
	encodeReflect(enc, reflect.ValueOf(v))
}

// interceptMarkers handles the marker types both dispatchers (encodeAny for
// interface values, encodeReflect for values reached through reflection)
// must special-case before any reflection sees them. Returns true when v was
// fully handled.
//
//   - vcvalue.Plain is the explicit passthrough opt-in; checked before Encryptable
//     and the struct arm so it is never mistaken for a plain struct.
//   - vcvalue.Object is decode-only in spirit, but a decrypt-then-re-encrypt flow
//     legitimately feeds it back in; without interception the reflect slice
//     arm would encode it as a SEQ of {Key,Value} structs, silently changing
//     the record's structure.
//   - Encryptable hands control to the user type — except a typed nil
//     pointer, which still satisfies the assertion but would dereference nil
//     in typical implementations; it encodes as Null like every other nil,
//     or as a typed null when the type declares its width (FixedWidth).
func interceptMarkers(enc Encoder, v any) bool {
	if m, ok := markers[reflect.TypeOf(v)]; ok {
		m.encode(enc, v)
		return true
	}
	if e, ok := v.(Encryptable); ok {
		if ev := reflect.ValueOf(e); ev.Kind() == reflect.Pointer && ev.IsNil() {
			if t, ok := fixedTypeOf(ev.Type()); ok {
				enc.TypedNull(t)
			} else {
				enc.Null()
			}
			return true
		}
		if err := e.EncryptValue(enc); err != nil {
			enc.st.fail(err)
		}
		return true
	}
	return false
}

// encodeObject re-encodes a decoded vcvalue.Object with object framing, preserving
// its field order (vcvalue.Object exists precisely to preserve wire order).
func encodeObject(enc Encoder, o vcvalue.Object) {
	m := enc.Map()
	for _, f := range o {
		encodeAny(m.Field(f.Key), f.Value)
	}
	_ = m.End()
}

func encodeReflect(enc Encoder, rv reflect.Value) {
	if enc.st.err != nil {
		return
	}
	if !rv.IsValid() {
		enc.Null()
		return
	}
	// Re-check the explicit markers for values reached through reflection
	// (struct fields, slice elements, map values). vcvalue.Plain is itself a struct,
	// so it must be intercepted before the reflect.Struct arm below.
	if rv.CanInterface() && interceptMarkers(enc, rv.Interface()) {
		return
	}

	if k, ok := numericKinds[rv.Kind()]; ok {
		k.encode(enc, rv)
		return
	}
	switch rv.Kind() {
	case reflect.Bool:
		enc.Bool(rv.Bool())
	case reflect.String:
		enc.String(rv.String())
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			enc.Bytes(rv.Bytes())
			return
		}
		encodeSeq(enc, rv)
	case reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// Byte arrays are one Bytes leaf, matching the slice arm above
			// and Rust's single-leaf [u8; N] — element-wise encoding would
			// seal N separate leaves and produce a ciphertext shape no other
			// producer emits.
			b := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(b), rv)
			enc.Bytes(b)
			return
		}
		encodeSeq(enc, rv)
	case reflect.Map:
		encodeMap(enc, rv)
	case reflect.Struct:
		encodeStruct(enc, rv)
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			// A nil pointer still has its element type, so an absent
			// fixed-width value is padded like Rust's Option<T>. A nil
			// interface has no type to go by.
			if rv.Kind() != reflect.Pointer {
				enc.Null()
			} else if t, ok := fixedTypeOf(rv.Type()); ok {
				enc.TypedNull(t)
			} else {
				enc.Null()
			}
			return
		}
		// Charge the dereference against the shared depth budget: it writes
		// no container framing, so without this a pointer cycle (x = &x)
		// would recurse to stack overflow instead of failing cleanly.
		if enc.depth+1 > maxDepth {
			enc.st.fail(ErrTooDeep)
			return
		}
		// Same slot: the dereferenced value completes the pointer's counter.
		encodeReflect(Encoder{st: enc.st, depth: enc.depth + 1, done: enc.done}, rv.Elem())
	default:
		enc.st.fail(fmt.Errorf("vcffi: cannot encode value of kind %s", rv.Kind()))
	}
}

func encodeSeq(enc Encoder, rv reflect.Value) {
	s := enc.Seq()
	for i := 0; i < rv.Len(); i++ {
		encodeReflect(s.Elem(), rv.Index(i))
	}
	_ = s.End()
}

func encodeMap(enc Encoder, rv reflect.Value) {
	if rv.Type().Key().Kind() != reflect.String {
		enc.st.fail(fmt.Errorf("vcffi: map keys must be strings, got %s", rv.Type().Key()))
		return
	}
	keys := rv.MapKeys()
	// Sort keys: Go map iteration is randomized; sorting makes the encrypted
	// structure deterministic across encodes of an equal map.
	slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
	m := enc.Map()
	for _, k := range keys {
		encodeReflect(m.Field(k.String()), rv.MapIndex(k))
	}
	_ = m.End()
}

func encodeStruct(enc Encoder, rv reflect.Value) {
	t := rv.Type()
	// Named as the storage profile names them: `vc:"name"`, options after
	// a comma, `vc:"-"` skipped, an unknown option refused.
	fields, err := structFields(t)
	if err != nil {
		enc.st.fail(err)
		return
	}
	m := enc.Map()
	encoded, unexported := 0, 0
	for _, f := range fields {
		if f.unexported {
			unexported++
			continue
		}
		encodeReflect(m.Field(f.name), rv.Field(f.index))
		encoded++
	}
	// A struct whose every field is unexported (time.Time is the canonical
	// case) would seal as an empty map and the payload would be gone with no
	// error at either end — the exact hazard the NAPI layer's
	// ensure_plain_object guards. An all-`vc:"-"` struct is left alone: the
	// caller asked for the empty encoding explicitly.
	if encoded == 0 && unexported > 0 {
		enc.st.fail(fmt.Errorf(
			"vcffi: struct %s has no exported fields to encode — implement Encryptable to control its sealing", t))
		return
	}
	_ = m.End()
}

// marker is how interceptMarkers writes a type it handles by exact type,
// and the fixed-width type of its typed null, if it has one (zero if not).
// One table for both, so a new marker type cannot be written one way and
// padded, or not, another.
type marker struct {
	fixed  vcvalue.FixedType
	encode func(Encoder, any)
}

// numeric is how encodeReflect writes an int, uint or float kind, and the
// fixed-width type of its typed null: the same one-table rule as marker.
type numeric struct {
	fixed  vcvalue.FixedType
	encode func(Encoder, reflect.Value)
}

var (
	encryptableType = reflect.TypeOf((*Encryptable)(nil)).Elem()
	fixedWidthType  = reflect.TypeOf((*FixedWidth)(nil)).Elem()
	float32Type     = reflect.TypeOf(float32(0))

	// markers is filled in init: Plain and Object encode by calling back
	// into encodeAny, which reads the table.
	markers map[reflect.Type]marker

	numericKinds = map[reflect.Kind]numeric{
		reflect.Int8:  {vcvalue.TypeInt8, func(e Encoder, rv reflect.Value) { e.Int8(int8(rv.Int())) }},
		reflect.Int16: {vcvalue.TypeInt16, func(e Encoder, rv reflect.Value) { e.Int16(int16(rv.Int())) }},
		reflect.Int32: {vcvalue.TypeInt32, func(e Encoder, rv reflect.Value) { e.Int32(int32(rv.Int())) }},
		reflect.Int:   {vcvalue.TypeInt64, func(e Encoder, rv reflect.Value) { e.Int64(rv.Int()) }},
		reflect.Int64: {vcvalue.TypeInt64, func(e Encoder, rv reflect.Value) { e.Int64(rv.Int()) }},
		reflect.Uint8: {vcvalue.TypeUint8, func(e Encoder, rv reflect.Value) { e.UInt8(uint8(rv.Uint())) }},
		reflect.Uint16: {vcvalue.TypeUint16, func(e Encoder, rv reflect.Value) {
			e.UInt16(uint16(rv.Uint()))
		}},
		reflect.Uint32: {vcvalue.TypeUint32, func(e Encoder, rv reflect.Value) {
			e.UInt32(uint32(rv.Uint()))
		}},
		// Every unsigned word-or-wider kind keeps its unsigned identity as
		// UInt64 (no fit-check: a bare uint always maps to UINT64).
		reflect.Uint:    {vcvalue.TypeUint64, func(e Encoder, rv reflect.Value) { e.UInt64(rv.Uint()) }},
		reflect.Uint64:  {vcvalue.TypeUint64, func(e Encoder, rv reflect.Value) { e.UInt64(rv.Uint()) }},
		reflect.Uintptr: {vcvalue.TypeUint64, func(e Encoder, rv reflect.Value) { e.UInt64(rv.Uint()) }},
		reflect.Float32: {vcvalue.TypeFloat32, func(e Encoder, rv reflect.Value) {
			// rv.Float() widens to float64, and the hardware widening sets
			// the quiet bit of a signaling NaN. Converting to the built-in
			// float32 instead copies the bits (reflect special-cases float32
			// to float32, Go issue 36400), so a named float32 type keeps
			// them too. Only a value that cannot be read as an interface
			// falls back to widening.
			if f, ok := interfaceOf(rv.Convert(float32Type)).(float32); ok {
				e.Float32(f)
			} else {
				e.Float32(float32(rv.Float()))
			}
		}},
		reflect.Float64: {vcvalue.TypeFloat64, func(e Encoder, rv reflect.Value) { e.Float64(rv.Float()) }},
	}

	// fixedTypes caches fixedTypeOf by pointer type: every nil pointer of a
	// record type would otherwise pay its reflection again.
	fixedTypes sync.Map
)

func init() {
	markers = map[reflect.Type]marker{
		reflect.TypeOf(vcvalue.Int128{}): {vcvalue.TypeInt128, func(e Encoder, v any) {
			e.Int128(v.(vcvalue.Int128))
		}},
		reflect.TypeOf(vcvalue.Uint128{}): {vcvalue.TypeUint128, func(e Encoder, v any) {
			e.UInt128(v.(vcvalue.Uint128))
		}},
		reflect.TypeOf(vcvalue.Date{}): {vcvalue.TypeDate, func(e Encoder, v any) {
			e.Date(v.(vcvalue.Date))
		}},
		reflect.TypeOf(time.Time{}): {vcvalue.TypeTimestamp, func(e Encoder, v any) {
			e.Timestamp(v.(time.Time))
		}},
		reflect.TypeOf(vcvalue.Timestamp{}): {vcvalue.TypeTimestamp, func(e Encoder, v any) {
			e.TimestampParts(v.(vcvalue.Timestamp))
		}},
		reflect.TypeOf(vcvalue.Decimal{}): {vcvalue.TypeDecimal, func(e Encoder, v any) {
			e.Decimal(v.(vcvalue.Decimal))
		}},
		reflect.TypeOf(vcvalue.UUID{}): {vcvalue.TypeUUID, func(e Encoder, v any) {
			e.UUID(v.(vcvalue.UUID))
		}},
		// A tagged value's physical type is in the value, not the type.
		reflect.TypeOf(vcvalue.Tagged{}): {0, func(e Encoder, v any) { e.Tagged(v.(vcvalue.Tagged)) }},
		reflect.TypeOf(vcvalue.TypedNull{}): {0, func(e Encoder, v any) {
			e.TypedNull(v.(vcvalue.TypedNull).Type)
		}},
		reflect.TypeOf(vcvalue.Plain{}): {0, func(e Encoder, v any) {
			encodeAny(e.Passthrough(), v.(vcvalue.Plain).V)
		}},
		reflect.TypeOf(vcvalue.Object{}): {0, func(e Encoder, v any) {
			encodeObject(e, v.(vcvalue.Object))
		}},
	}
}

// fixedAnswer is what fixedTypeOf caches: whether the type has a fixed-width
// type at all, and which. A type declared through FixedWidth is kept even
// when it is invalid, so that the encode fails instead of writing the plain
// null in its place.
type fixedAnswer struct {
	ft  vcvalue.FixedType
	has bool
}

// fixedTypeOf is the fixed-width type a pointer of type t points at, through
// any number of pointers, when encodeReflect writes every value of it with
// one fixed-width tag: the int, uint and float kinds (a named type over one
// included) and the fixed-width marker types, exactly (a named type over a
// marker is a struct to reflection, written field by field). A type that
// implements Encryptable chooses its own encoding, which may not be fixed
// width, so it has none unless it says so through FixedWidth.
func fixedTypeOf(t reflect.Type) (vcvalue.FixedType, bool) {
	if cached, ok := fixedTypes.Load(t); ok {
		a := cached.(fixedAnswer)
		return a.ft, a.has
	}
	var a fixedAnswer
	elem := t
	// A pointer type that points at itself (type P *P) never reaches a
	// non-pointer, so the walk is bounded by the same depth budget that
	// bounds a value cycle. Past it the type has no fixed width.
	for depth := 0; elem.Kind() == reflect.Pointer && !elem.Implements(encryptableType); depth++ {
		if depth == maxDepth {
			fixedTypes.Store(t, a)
			return 0, false
		}
		elem = elem.Elem()
	}
	switch {
	case elem.Implements(fixedWidthType):
		a = fixedAnswer{zeroValueOf(elem).Interface().(FixedWidth).FixedType(), true}
	case elem.Implements(encryptableType):
		// Its encoding is its own.
	default:
		if m, ok := markers[elem]; ok {
			a.ft = m.fixed
		} else {
			a.ft = numericKinds[elem.Kind()].fixed
		}
		a.has = a.ft != 0
	}
	fixedTypes.Store(t, a)
	return a.ft, a.has
}

// zeroValueOf is a zero value of t that a method can be called on: for a
// pointer type, a pointer to a zero value rather than nil, so a method with
// a value receiver does not dereference nil.
func zeroValueOf(t reflect.Type) reflect.Value {
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem())
	}
	return reflect.Zero(t)
}

// interfaceOf is rv.Interface(), or nil where reflection forbids it
// (values reached through unexported fields).
func interfaceOf(rv reflect.Value) any {
	if !rv.CanInterface() {
		return nil
	}
	return rv.Interface()
}
