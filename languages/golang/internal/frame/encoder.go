package frame

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
)

// encState is the buffer and the first error of one encode. An Encoder
// shares it with every Encoder made from it. After the first error is
// recorded, every later write does nothing. Code that writes a value can
// therefore make several writes without a check after each one. End and
// Marshal return the first error.
type encState struct {
	buf []byte
	err error
}

func (s *encState) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// Encoder records one value as transport bytes. The methods of an Encoder
// match the methods of the Rust Cipher. An Encoder only writes bytes. An
// Encoder does not encrypt.
//
// Call exactly one method on an Encoder. That method is one of these:
//
//   - A method that writes a scalar: Null, Undefined, Bool, String, Bytes,
//     Date, Timestamp, TimestampParts, Decimal, UUID, Tagged, or one of the
//     integer and float methods. The scalar methods are in this file and in
//     scalars.go.
//   - A method that starts a container: Seq or Map.
//
// Pass and store an Encoder by value. Every Encoder of one encode points at
// the same buffer and the same first error, so a copy is cheap and safe.
//
// The zero Encoder is not usable, and its methods panic. A usable Encoder
// comes from one of two places:
//
//   - The codec gives one to a published Encryptable. See
//     [PublishEncryptable].
//   - Passthrough, Elem, and Field each return one.
//
// [Encoder.Usable] reports whether an Encoder is usable.
type Encoder struct {
	st    *encState
	depth int
	// done points at the counter for the slot that this Encoder writes into.
	// A slot is the place for one value: the root, one element of a
	// sequence, or the value of one map entry. A scalar method adds one to
	// the counter. The End of a container adds one too. The owner of the
	// slot then checks that the counter is exactly one.
	//
	// Each slot has a counter of its own. With one counter for the whole
	// encode, a value completed deeper in the tree could count as the value
	// of the slot. An example is a scalar inside a nested container that was
	// never ended. A decoder would then read the bytes that follow as the
	// wrong values. The only sign would be ErrMalformed at decode.
	done *int
}

func (e Encoder) push(b ...byte) {
	e.st.buf = append(e.st.buf, b...)
}

// complete records that the slot of this Encoder received one complete
// value.
func (e Encoder) complete() {
	if e.done != nil {
		*e.done++
	}
}

// Null records a null. A null is nil in Go, null in JavaScript, and None in
// Python.
func (e Encoder) Null() {
	if e.st.err == nil {
		e.push(tagNull)
		e.complete()
	}
}

// Undefined records the JavaScript value undefined. Go has no such value, so
// Go code rarely calls this method. The method exists so that a value
// decoded from JavaScript can be encoded again. An undefined decodes as nil,
// as a null does.
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

// Float64 records a 64-bit IEEE 754 float. The value decodes as a 64-bit
// float in every language, never as an integer. Float64 writes the bits of f
// unchanged, so a NaN keeps its payload and -0.0 keeps its sign.
func (e Encoder) Float64(f float64) {
	if e.st.err != nil {
		return
	}
	e.push(tagFloat64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, math.Float64bits(f))
	e.complete()
}

// Float32 records a 32-bit IEEE 754 float. To match the float4 type of EQL,
// the encoding keeps the 32-bit width. Float32 writes the bits of f
// unchanged.
func (e Encoder) Float32(f float32) {
	if e.st.err != nil {
		return
	}
	e.push(tagFloat32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, math.Float32bits(f))
	e.complete()
}

// Int32 records a signed 32-bit integer. To match the int4 type of EQL, the
// encoding keeps an Int32 distinct from an Int64.
func (e Encoder) Int32(i int32) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, uint32(i))
	e.complete()
}

// Int64 records a signed 64-bit integer. The encoding keeps an Int64
// distinct from a Float64. A language that has integer types therefore
// decodes an integer as an integer.
func (e Encoder) Int64(i int64) {
	if e.st.err != nil {
		return
	}
	e.push(tagInt64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, uint64(i))
	e.complete()
}

// Uint32 records an unsigned 32-bit integer. To match the types of an EQL
// schema, the encoding keeps the 32-bit width.
func (e Encoder) Uint32(u uint32) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint32)
	e.st.buf = binary.LittleEndian.AppendUint32(e.st.buf, u)
	e.complete()
}

// Uint64 records an unsigned 64-bit integer without changing its width.
func (e Encoder) Uint64(u uint64) {
	if e.st.err != nil {
		return
	}
	e.push(tagUint64)
	e.st.buf = binary.LittleEndian.AppendUint64(e.st.buf, u)
	e.complete()
}

// String records a string. The encode fails if s is not valid UTF-8.
func (e Encoder) String(s string) {
	if e.st.err != nil {
		return
	}
	if !utf8.ValidString(s) {
		e.st.fail(errors.New("frame: string is not valid UTF-8"))
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

// Bytes records binary data.
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

// Passthrough marks the next value as passthrough, and returns an Encoder
// for that value. A passthrough value is neither encrypted nor
// authenticated, so use Passthrough only for data that is not secret.
//
// The returned Encoder has the same methods as any other Encoder:
//
//	m.Field("id").Passthrough().Int64(42)   // a passthrough map entry
//	enc.Passthrough().String("v")           // a passthrough root value
//	s.Elem().Passthrough().Bool(true)       // a passthrough sequence element
//
// Write exactly one value through the returned Encoder: a scalar or a
// container.
func (e Encoder) Passthrough() Encoder {
	if e.st.err == nil {
		if e.depth+1 > maxDepth {
			e.st.fail(ErrTooDeep)
		} else {
			e.push(tagPassthrough)
		}
	}
	// The passthrough tag and the value after it are one value in the slot
	// of this Encoder. The returned Encoder therefore uses the same counter.
	return Encoder{st: e.st, depth: e.depth + 1, done: e.done}
}

// Seq starts a sequence. Call Elem once for each element, then call End.
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
	e.push(0, 0, 0, 0) // End writes the count here
	return s
}

// Map starts a map with string keys. Call Field once for each entry, then
// call End. The entries are encoded in the order of the Field calls. Each
// key must be valid UTF-8.
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
	e.push(0, 0, 0, 0) // End writes the count here
	return m
}

// SeqEncoder records the elements of a sequence. Seq reserves four bytes for
// the element count, and End writes the count into them.
type SeqEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
	// done is the counter of the slot that the sequence is written into. See
	// Encoder.done. End adds one to the counter, because the sequence is one
	// value in that slot.
	done *int
	// childDone counts the elements of this sequence that are complete. Elem
	// and End check that childDone equals count. The encode therefore fails
	// for an element that was skipped, an element written twice, or a nested
	// container that was never ended. Without the check, those mistakes
	// would appear only as ErrMalformed at decode.
	childDone int
}

// checkPrev checks that exactly one value was written for the previous
// element.
func (s *SeqEncoder) checkPrev() {
	if s.childDone > s.count {
		s.st.fail(fmt.Errorf("frame: more than one value was written for sequence element %d", s.count-1))
	} else if s.count > 0 && s.childDone < s.count {
		s.st.fail(fmt.Errorf("frame: sequence element %d was never completed", s.count-1))
	}
}

// Elem returns an Encoder for the next element. Write the whole element
// before the next call to Elem: call one method, and end any container that
// it starts.
func (s *SeqEncoder) Elem() Encoder {
	if s.st.err == nil {
		s.checkPrev()
		if s.st.err == nil {
			s.count++
		}
	}
	return Encoder{st: s.st, depth: s.depth, done: &s.childDone}
}

// End completes the sequence and writes its element count.
//
// End returns the first error of the whole encode so far. The error is not
// limited to this sequence, so the End of a nested container can return an
// error from another part of the tree. This rule is deliberate. A later
// release will not change it.
//
// After the first error, every later write does nothing. An EncryptValue
// method can therefore make its writes without a check after each one, and
// return the result of the outermost End. Do not use the error of an inner
// End to find which value failed. The text of the error names that value.
func (s *SeqEncoder) End() error {
	if s.st.err == nil {
		s.checkPrev()
	}
	err := patchLen(s.st, s.lenOff, s.count)
	if err == nil {
		// The sequence is one complete value in the slot it was written
		// into.
		if s.done != nil {
			*s.done++
		}
	}
	return err
}

// MapEncoder records the entries of a map. Map reserves four bytes for the
// entry count, and End writes the count into them.
type MapEncoder struct {
	st     *encState
	depth  int
	lenOff int
	count  int
	// done is the counter of the slot that the map is written into. See
	// Encoder.done. End adds one to the counter, because the map is one
	// value in that slot.
	done *int
	// childDone counts the entries of this map whose values are complete, as
	// SeqEncoder.childDone does for elements. Field and End check that
	// childDone equals count. The encode therefore fails for a key whose
	// value was skipped, written twice, or left as a container that was
	// never ended. Without the check, a decoder would read the next key as
	// the missing value. The only sign would be ErrMalformed at decode.
	childDone int
	// lastKey is the key of the most recent Field call. An error about a
	// value that was skipped or written twice names this key.
	lastKey string
	// seen is the set of keys written so far. Field uses it to refuse a
	// duplicate key. A Go map never has a duplicate key. Two other sources
	// can produce one:
	//
	//   - encodeStruct, when the vc tag of one field is the name of another
	//     field
	//   - an Encryptable written by hand
	//
	// Without this check, the duplicate would be found only after the
	// plaintext has crossed into the guest. The ciphertext decoder would
	// then return ErrMalformed. That error names neither the struct nor the
	// key.
	seen map[string]struct{}
}

// checkPrev checks that exactly one value was written for the previous
// entry.
func (m *MapEncoder) checkPrev() {
	if m.childDone > m.count {
		m.st.fail(fmt.Errorf("frame: more than one value was written for key %q", m.lastKey))
	} else if m.count > 0 && m.childDone < m.count {
		m.st.fail(fmt.Errorf("frame: value for key %q was never completed", m.lastKey))
	}
}

// Field writes the key of an entry and returns an Encoder for its value.
// Write the whole value before the next call to Field: call one method, and
// end any container that it starts. The key must be valid UTF-8. A key that
// repeats an earlier key fails the encode. The entries are encoded in the
// order of the Field calls.
func (m *MapEncoder) Field(key string) Encoder {
	if m.st.err == nil {
		m.checkPrev()
	}
	if m.st.err == nil {
		if !utf8.ValidString(key) {
			m.st.fail(errors.New("frame: object key is not valid UTF-8"))
		} else if _, dup := m.seen[key]; dup {
			m.st.fail(fmt.Errorf("frame: duplicate key %q in map encoding", key))
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

// End completes the map and writes its entry count. End returns the first
// error of the whole encode, as [SeqEncoder.End] does. The error is not
// limited to this map.
func (m *MapEncoder) End() error {
	if m.st.err == nil {
		m.checkPrev()
	}
	err := patchLen(m.st, m.lenOff, m.count)
	if err == nil {
		// The map is one complete value in the slot it was written into.
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
		st.fail(fmt.Errorf("frame: item count %d out of range", count))
		return st.err
	}
	binary.LittleEndian.PutUint32(st.buf[off:off+4], uint32(count))
	return nil
}

// Marshal encodes v as the transport bytes of a value. A guest reads a value
// in that form, and [Unmarshal] decodes it.
func Marshal(v any) ([]byte, error) {
	st := &encState{}
	var root int
	if err := Encode(Encoder{st: st, done: &root}, v); err != nil {
		return nil, err
	}
	// The reflection code always writes exactly one value. Only an
	// Encryptable can write no value, leave a container without its End, or
	// write more than one value.
	if root != 1 {
		return nil, fmt.Errorf("frame: encode must complete exactly one root value, completed %d", root)
	}
	return st.buf, nil
}

// Encode records v into enc. Encode first checks whether v implements the
// published Encryptable interface. If v does, Encode calls its EncryptValue
// method. Otherwise Encode chooses a method by the type of v, with rules
// like those of encoding/json:
//
//   - nil is written with Null.
//   - A bool is written with Bool.
//   - An int8, int16, or int32 is written with Int8, Int16, or Int32.
//   - An int or int64 is written with Int64.
//   - A uint8, uint16, or uint32 is written with Uint8, Uint16, or Uint32.
//   - A uint, uint64, or uintptr is written with Uint64.
//   - A float32 is written with Float32.
//   - A float64 is written with Float64.
//   - A string is written with String.
//   - A []byte is written with Bytes.
//   - A slice or an array is written with Seq.
//   - A map[string]T is written with Map, with its keys in sorted order.
//   - A struct is written with Map, with one entry for each field, in the
//     order the struct declares them. The key is the field name, or the name
//     in a `vc:"name"` tag. A `vc:"-"` tag skips the field. Options after a
//     comma do not change the name. One such option is `,default` of the
//     storage profile.
//   - A pointer is written as the value it points at. A nil pointer is
//     written as a typed null if its element type has a fixed width, and
//     with Null otherwise. See [typedNullOf].
//
// Encode sorts the keys of a map because Go iterates over a map in a random
// order. Sorted keys give equal maps the same encrypted structure. The
// fields of a struct stay in the order the struct declares them.
//
// Encode returns the first error recorded while it wrote to enc. An
// Encryptable can therefore pass part of its value to Encode, as in
// Encode(m.Field(k), x).
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

// interceptMarkers writes v if the codec handles its type before reflection,
// and reports whether it wrote v. Both encodeAny and encodeReflect call it:
// the first for an interface value, the second for a value reached through
// reflection.
//
// The function handles these types:
//
//   - Plain marks a passthrough value. The function checks for Plain before
//     Encryptable and before the struct case, so a Plain is never encoded as
//     an ordinary struct.
//   - Object is what a map decodes as. A program that decrypts a record and
//     encrypts it again passes an Object back in. Without this case,
//     reflection would encode the Object as a sequence of structs with Key
//     and Value fields. The structure of the record would change, with no
//     error.
//   - A published type is encoded as the value type that it is published
//     for.
//   - A type that implements Encryptable writes itself. A nil pointer of
//     such a type is the exception. The pointer implements the interface,
//     but most EncryptValue methods would dereference it. The function
//     writes it with Null, as for any other nil whose type has no fixed
//     width.
func interceptMarkers(enc Encoder, v any) bool {
	v = internal(v)
	if m, ok := markers[reflect.TypeOf(v)]; ok {
		m.encode(enc, v)
		return true
	}
	if write, ok := encryptableOf(v); ok {
		if ev := reflect.ValueOf(v); ev.Kind() == reflect.Pointer && ev.IsNil() {
			enc.Null()
			return true
		}
		if err := write(enc); err != nil {
			enc.st.fail(err)
		}
		return true
	}
	return false
}

// encodeObject writes a decoded Object as a map, with its fields in the
// order the Object lists them. Object exists to keep that order.
func encodeObject(enc Encoder, o Object) {
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
	// A value reached through reflection can have one of the types that
	// interceptMarkers handles. Such a value is a struct field, a slice
	// element, or a map value. Plain is a struct, so this check must come
	// before the reflect.Struct case below.
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
			// A byte array is written as one Bytes value, as a byte slice is
			// above. Rust writes a [u8; N] as one leaf too. Writing each
			// byte as an element would seal N leaves. No other encoder
			// produces a ciphertext of that structure.
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
			// A nil pointer still has an element type. If that type has a
			// fixed width, the absent value is written as a typed null, as
			// Rust writes an Option<T>. A nil interface has no type, so it
			// is written with Null.
			if rv.Kind() != reflect.Pointer {
				enc.Null()
			} else if null := typedNullOf(rv.Type()); null != nil {
				enc.typedNull(null)
			} else {
				enc.Null()
			}
			return
		}
		// Count the dereference as one level of depth. A dereference writes
		// no bytes, so nothing else would limit a pointer cycle such as x =
		// &x. Without this check, a cycle would overflow the stack and
		// return no error.
		if enc.depth+1 > maxDepth {
			enc.st.fail(ErrTooDeep)
			return
		}
		// The value the pointer points at is written into the same slot, so
		// it uses the same counter.
		encodeReflect(Encoder{st: enc.st, depth: enc.depth + 1, done: enc.done}, rv.Elem())
	default:
		enc.st.fail(fmt.Errorf("frame: cannot encode value of kind %s", rv.Kind()))
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
		enc.st.fail(fmt.Errorf("frame: map keys must be strings, got %s", rv.Type().Key()))
		return
	}
	keys := rv.MapKeys()
	// Sort the keys. Go iterates over a map in a random order. Sorted keys
	// give equal maps the same encrypted structure.
	slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
	m := enc.Map()
	for _, k := range keys {
		encodeReflect(m.Field(k.String()), rv.MapIndex(k))
	}
	_ = m.End()
}

func encodeStruct(enc Encoder, rv reflect.Value) {
	t := rv.Type()
	// The fields are named as the storage profile names them. A `vc:"name"`
	// tag sets the name, and options follow a comma. A `vc:"-"` tag skips
	// the field. An unknown option is refused.
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
	// Refuse a struct whose fields are all unexported. time.Time is the
	// usual example. Such a struct would be sealed as an empty map. The
	// value would be lost, with no error at encode or at decode. The Node
	// binding of vitaminc has the same check, in ensure_plain_object. A
	// struct whose fields all have a `vc:"-"` tag is accepted, because the
	// caller asked for the empty encoding.
	if encoded == 0 && unexported > 0 {
		enc.st.fail(fmt.Errorf(
			"frame: struct %s has no exported fields to encode — implement Encryptable to control its sealing", t))
		return
	}
	_ = m.End()
}

// marker is one entry of the markers table. The encode function writes a
// value of a type that interceptMarkers matches exactly. The null field is
// the typed null of that type, or nil if the type has no fixed width.
//
// One table has both, so a new type cannot be written in one way and padded
// in another. A typed null is built from the tag that a value of the type is
// written with. The tag table is therefore the only list of types.
type marker struct {
	null   []byte
	encode func(Encoder, any)
}

// numeric is one entry of the numericKinds table. The encode function writes
// a value of an int, uint, or float kind for encodeReflect. The null field
// is the typed null of that kind. One table has both, as for marker.
type numeric struct {
	null   []byte
	encode func(Encoder, reflect.Value)
}

var (
	float32Type = reflect.TypeOf(float32(0))

	// markers is filled in init because the entries for Plain and Object
	// call encodeAny, and encodeAny reads this table.
	markers map[reflect.Type]marker

	numericKinds = map[reflect.Kind]numeric{
		reflect.Int8:  {nullOf(tagInt8), func(e Encoder, rv reflect.Value) { e.Int8(int8(rv.Int())) }},
		reflect.Int16: {nullOf(tagInt16), func(e Encoder, rv reflect.Value) { e.Int16(int16(rv.Int())) }},
		reflect.Int32: {nullOf(tagInt32), func(e Encoder, rv reflect.Value) { e.Int32(int32(rv.Int())) }},
		reflect.Int:   {nullOf(tagInt64), func(e Encoder, rv reflect.Value) { e.Int64(rv.Int()) }},
		reflect.Int64: {nullOf(tagInt64), func(e Encoder, rv reflect.Value) { e.Int64(rv.Int()) }},
		reflect.Uint8: {nullOf(tagUint8), func(e Encoder, rv reflect.Value) { e.Uint8(uint8(rv.Uint())) }},
		reflect.Uint16: {nullOf(tagUint16), func(e Encoder, rv reflect.Value) {
			e.Uint16(uint16(rv.Uint()))
		}},
		reflect.Uint32: {nullOf(tagUint32), func(e Encoder, rv reflect.Value) {
			e.Uint32(uint32(rv.Uint()))
		}},
		// A uint, uint64, or uintptr is always written as a Uint64. The
		// codec never checks whether the value would fit a narrower or a
		// signed type.
		reflect.Uint:    {nullOf(tagUint64), func(e Encoder, rv reflect.Value) { e.Uint64(rv.Uint()) }},
		reflect.Uint64:  {nullOf(tagUint64), func(e Encoder, rv reflect.Value) { e.Uint64(rv.Uint()) }},
		reflect.Uintptr: {nullOf(tagUint64), func(e Encoder, rv reflect.Value) { e.Uint64(rv.Uint()) }},
		reflect.Float32: {nullOf(tagFloat32), func(e Encoder, rv reflect.Value) {
			// rv.Float() widens the value to float64. On the hardware,
			// widening sets the quiet bit of a signaling NaN. A conversion
			// to the built-in float32 copies the bits unchanged, because
			// reflect treats a conversion from float32 to float32 as a copy.
			// See Go issue 36400. A named float32 type therefore keeps its
			// bits too.
			//
			// Only a value that cannot be read as an interface is widened.
			if f, ok := interfaceOf(rv.Convert(float32Type)).(float32); ok {
				e.Float32(f)
			} else {
				e.Float32(float32(rv.Float()))
			}
		}},
		reflect.Float64: {nullOf(tagFloat64), func(e Encoder, rv reflect.Value) { e.Float64(rv.Float()) }},
	}

	// typedNulls caches the result of typedNullOf for each pointer type.
	// Without the cache, every nil pointer in a record would repeat the
	// reflection.
	typedNulls sync.Map
)

func init() {
	markers = map[reflect.Type]marker{
		reflect.TypeOf(Int128{}): {nullOf(tagInt128), func(e Encoder, v any) {
			e.Int128(v.(Int128))
		}},
		reflect.TypeOf(Uint128{}): {nullOf(tagUint128), func(e Encoder, v any) {
			e.Uint128(v.(Uint128))
		}},
		reflect.TypeOf(Date{}): {nullOf(tagDate), func(e Encoder, v any) {
			e.Date(v.(Date))
		}},
		reflect.TypeOf(time.Time{}): {nullOf(tagTimestamp), func(e Encoder, v any) {
			e.Timestamp(v.(time.Time))
		}},
		reflect.TypeOf(Timestamp{}): {nullOf(tagTimestamp), func(e Encoder, v any) {
			e.TimestampParts(v.(Timestamp))
		}},
		reflect.TypeOf(Decimal{}): {nullOf(tagDecimal), func(e Encoder, v any) {
			e.Decimal(v.(Decimal))
		}},
		reflect.TypeOf(UUID{}): {uuidNull, func(e Encoder, v any) {
			e.UUID(v.(UUID))
		}},
		// The scalar type of a Tagged is known only from its value, so
		// Tagged has no typed null.
		reflect.TypeOf(Tagged{}): {nil, func(e Encoder, v any) { e.Tagged(v.(Tagged)) }},
		reflect.TypeOf(Plain{}): {nil, func(e Encoder, v any) {
			encodeAny(e.Passthrough(), v.(Plain).V)
		}},
		reflect.TypeOf(Object{}): {nil, func(e Encoder, v any) {
			encodeObject(e, v.(Object))
		}},
	}
}

// typedNullOf returns the typed null for a nil pointer of type t. The
// function follows t through any number of pointers to the type at the end.
// That type has a typed null when encodeReflect writes every value of it
// with one fixed-width tag. Two groups of types qualify:
//
//   - The int, uint, and float kinds. A named type over one of these kinds
//     qualifies too.
//   - The fixed-width types in the markers table, matched exactly. A named
//     type over one of them does not qualify. Reflection reads such a type
//     as a struct, and writes it field by field.
//
// The result is nil for any other type. A type that implements Encryptable
// has no typed null either. Such a type chooses its own encoding, and that
// encoding might not have a fixed width.
func typedNullOf(t reflect.Type) []byte {
	if cached, ok := typedNulls.Load(t); ok {
		return cached.([]byte)
	}
	var null []byte
	elem := t
	// A pointer type can point at itself, as in type P *P. Such a type never
	// leads to a type that is not a pointer. The loop therefore stops after
	// maxDepth steps, the same limit as for a cycle of values. A type beyond
	// that limit has no fixed width.
	for depth := 0; elem.Kind() == reflect.Pointer && !implementsEncryptable(elem); depth++ {
		if depth == maxDepth {
			typedNulls.Store(t, null)
			return nil
		}
		elem = elem.Elem()
	}
	if !implementsEncryptable(elem) {
		if m, ok := markers[internalType(elem)]; ok {
			null = m.null
		} else {
			null = numericKinds[elem.Kind()].null
		}
	}
	typedNulls.Store(t, null)
	return null
}

// interfaceOf returns rv.Interface(). The result is nil when reflection does
// not allow the call, as for a value reached through an unexported field.
func interfaceOf(rv reflect.Value) any {
	if !rv.CanInterface() {
		return nil
	}
	return rv.Interface()
}
