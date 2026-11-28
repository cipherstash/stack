package frame

import (
	"cmp"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// This file is the storage profile, version 1. The storage profile writes a
// value as one versioned blob, for bytes that a program stores. The Rust
// module recipher_frame::storage implements the same format. The file
// packages/recipher-frame/STORAGE.md specifies the format. The tests check
// it against the expected blobs in
// packages/recipher-frame/testdata/storage-v1.json.
//
// The rest of this package writes transport bytes, and a later release can
// change those. A later release never changes the bytes that
// [MarshalStorage] writes and [UnmarshalStorage] reads. Go and Rust both
// read and write them.

// StorageVersion is the version that this package writes. No other version
// is read.
const StorageVersion = 1

// StorageSome is the tag of an optional value that is present. The bytes are
// StorageSome, then the value. Rust writes the tag for every Some.
//
// Go writes the tag only for a pointer to a value that is itself written
// starting with null or StorageSome. Without the tag, such a pointer would
// read back as nil. In every other case Go writes the value with no tag.
//
// A reader accepts a value with no tag as a present value, for a Go pointer
// and for a Rust Option. A reader also accepts it for a field that is not
// optional. Both languages therefore read what a Go pointer wrote, whatever
// type the reader declares.
const StorageSome = 0xF5

// StorageMap is the tag of a map whose keys are nodes. The bytes are
// StorageMap, a 32-bit count, then a key and a value for each entry. A Go
// map is written as such a map. A struct is written as an object.
const StorageMap = 0xF6

// StorageHeader is the four bytes that start every blob: "VCS", then
// [StorageVersion].
var StorageHeader = [4]byte{'V', 'C', 'S', StorageVersion}

// The kinds of error that the storage profile returns. The kinds correspond
// to storage::ErrorKind in Rust. Match them with errors.Is. A blob that
// breaks a rule of its version fails with [ErrMalformed], as malformed
// transport bytes do.
var (
	// ErrNotABlob means that the bytes are shorter than the header, or do
	// not start with "VCS".
	ErrNotABlob = errors.New("frame: not a storage blob")
	// ErrUnsupportedVersion means that the blob has a version that this
	// package does not read. The blob is not corrupt. A later release of
	// this package might read it, so upgrade the reader.
	ErrUnsupportedVersion = errors.New("frame: an unsupported storage version")
	// ErrMismatch means that a well-formed blob contains a value that does
	// not fit the destination. Examples are a string where a number is
	// expected, and a missing field.
	ErrMismatch = errors.New("frame: the stored value does not fit the destination")
	// ErrUnwritable means that the value cannot be written as a blob. The
	// causes are these:
	//
	//   - The value is nested too deep.
	//   - A map key is not an integer, text, or bytes.
	//   - A key is repeated.
	//   - The value is of a kind that has no storage form.
	ErrUnwritable = errors.New("frame: the value cannot be written as a storage blob")
)

// Some is an optional value that is present, as a blob stores it.
// UnmarshalStorage returns a Some when it reads such a value into an `any`.
// To write an optional value, the usual way is a pointer.
type Some struct {
	V any
}

// StorageEntries is a map as a blob stores it: the entries, in the order
// they were written. UnmarshalStorage returns a StorageEntries when it reads
// a map into an `any`. Each key is an integer, a string, or a []byte.
// MarshalStorage writes a StorageEntries as a map, with the entries in the
// same order.
type StorageEntries []StorageEntry

// StorageEntry is one entry of [StorageEntries].
type StorageEntry struct {
	Key   any
	Value any
}

func unwritable(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnwritable}, args...)...)
}

// MarshalStorage writes v as a version 1 blob. The type of v decides how it
// is written:
//
//   - nil and a nil interface are written as null.
//   - A bool is written as a bool.
//   - An int8, int16, int32, or int64 is written at its own width. An int is
//     written as an int64.
//   - A uint8, uint16, uint32, or uint64 is written at its own width. A uint
//     or uintptr is written as a uint64.
//   - An Int128 or Uint128 is written as a 128-bit integer.
//   - A float32 or float64 is written at its own width, with its bits
//     unchanged.
//   - A string is written as text. The string must be valid UTF-8.
//   - A []byte or [N]byte is written as bytes. A UUID is therefore written
//     as its 16 bytes.
//   - A type that implements encoding.TextMarshaler is written as text. A
//     time.Time is therefore written in RFC 3339 form.
//   - A slice or an array is written as an array. A nil slice is written as
//     an empty array.
//   - A map[K]V is written as a map, with its keys in sorted order. The
//     order of integer keys is by value. The order of text keys and of bytes
//     keys is by their bytes. A Rust BTreeMap has the same order. K must be
//     an integer, a string, a byte array, or a TextMarshaler.
//   - A struct is written as an object, with one entry for each field, in
//     the order the struct declares them. The key is the field name, or the
//     name in a `vc:"name"` tag. A `vc:"-"` tag skips the field. A field
//     tagged `vc:"name,default"` reads as its zero value from a blob that
//     does not have it.
//   - A nil pointer is written as null. Any other pointer is written as the
//     value it points at, as encoding/json does. One case differs: a pointer
//     to a value whose bytes start with null or [StorageSome]. Such a value
//     is a nil pointer, a nil interface, a [Some], or a pointer to one of
//     those. The pointer is then written as [StorageSome] followed by the
//     value, so every level of pointer reads back.
//   - A [Some], a [StorageEntries], an Object, and a []any are each written
//     as the node they are read from.
//
// Some types of the transport encoding have no storage form. MarshalStorage
// refuses them: an Encryptable, the passthrough type Plain, and the logical
// types Date, Timestamp, Decimal, and Tagged.
func MarshalStorage(v any) ([]byte, error) {
	w := &storageWriter{buf: append([]byte(nil), StorageHeader[:]...)}
	if err := w.any(v, 0); err != nil {
		return nil, err
	}
	return w.buf, nil
}

type storageWriter struct {
	buf []byte
}

var (
	textMarshalerType   = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
)

func (w *storageWriter) any(v any, depth int) error {
	return w.reflect(reflect.ValueOf(v), depth)
}

// The types of this package that [storageWriter.model] writes. Int128 and
// Uint128 are [16]byte types, so [byteArray] excludes them too. That second
// check covers a value that model cannot read as an interface. The reader
// relies on it as well.
var (
	int128Type    = reflect.TypeOf(Int128{})
	uint128Type   = reflect.TypeOf(Uint128{})
	someType      = reflect.TypeOf(Some{})
	objectType    = reflect.TypeOf(Object{})
	entriesType   = reflect.TypeOf(StorageEntries{})
	plainType     = reflect.TypeOf(Plain{})
	dateType      = reflect.TypeOf(Date{})
	timestampType = reflect.TypeOf(Timestamp{})
	decimalType   = reflect.TypeOf(Decimal{})
	taggedType    = reflect.TypeOf(Tagged{})
)

// model writes rv if its type is one of the types declared in this package,
// and reports whether it wrote rv. Each of those types has a storage form of
// its own, different from the form reflection would give it. Only a value of
// those types is converted to an interface to be written.
func (w *storageWriter) model(rv reflect.Value, depth int) (bool, error) {
	if !rv.CanInterface() {
		return false, nil
	}
	// A published type is written as the value type that it is published
	// for. An error names the type that the program used.
	given := rv.Type()
	rv = internalValue(rv)
	switch rv.Type() {
	case someType:
		w.buf = append(w.buf, StorageSome)
		return true, w.any(rv.Interface().(Some).V, depth+1)
	case objectType:
		return true, w.object(rv.Interface().(Object), depth)
	case entriesType:
		return true, w.entries(rv.Interface().(StorageEntries), depth)
	case int128Type:
		x := rv.Interface().(Int128)
		w.buf = append(append(w.buf, tagInt128), x[:]...)
		return true, nil
	case uint128Type:
		x := rv.Interface().(Uint128)
		w.buf = append(append(w.buf, tagUint128), x[:]...)
		return true, nil
	case plainType, dateType, timestampType, decimalType, taggedType:
		return true, unwritable("%s has no storage form", given)
	}
	return false, nil
}

func (w *storageWriter) reflect(rv reflect.Value, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: %w", ErrUnwritable, ErrTooDeep)
	}
	if !rv.IsValid() {
		w.buf = append(w.buf, tagNull)
		return nil
	}
	// This check is by type, and comes before a nil pointer is written as
	// null. A field of an Encryptable type is therefore refused even when it
	// is nil.
	if encryptable(rv.Type()) {
		return unwritable("%s implements Encryptable, which has no storage form", rv.Type())
	}
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		return w.indirect(rv, depth)
	}
	if handled, err := w.model(rv, depth); handled {
		return err
	}
	if byteArray(rv.Type()) {
		return w.bytes(arrayBytes(rv))
	}
	if text, ok, err := marshalText(rv); ok {
		if err != nil {
			return unwritable("the MarshalText method of %s returned an error", rv.Type())
		}
		return w.text(text)
	}
	if k, ok := numericKinds[rv.Kind()]; ok {
		// The numeric table of the transport encoding writes each kind as a
		// blob does: the same tag and the same width. The two encodings
		// differ only in the bytes around a value, and a number has none.
		st := &encState{buf: w.buf}
		k.encode(Encoder{st: st}, rv)
		w.buf = st.buf
		return st.err
	}
	switch rv.Kind() {
	case reflect.Bool:
		if rv.Bool() {
			w.buf = append(w.buf, tagTrue)
		} else {
			w.buf = append(w.buf, tagFalse)
		}
		return nil
	case reflect.String:
		return w.text([]byte(rv.String()))
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return w.bytes(rv.Bytes())
		}
		return w.array(rv, depth)
	case reflect.Array:
		return w.array(rv, depth)
	case reflect.Map:
		return w.goMap(rv, depth)
	case reflect.Struct:
		return w.goStruct(rv, depth)
	}
	return unwritable("a value of kind %s has no storage form", rv.Kind())
}

// indirect writes the value that the pointer or interface rv refers to. A
// nil rv is written as null. Otherwise the value is written, after
// [StorageSome] if the value starts with null or StorageSome. See
// [startsOptional].
//
// StorageSome is a node, so it counts as one level of depth, as a reader
// counts it. A pointer or an interface that writes no bytes of its own adds
// no depth, because the blob is no deeper for it. A chain of those has a
// separate limit. A cycle such as p = &p is therefore refused, and the loop
// ends.
func (w *storageWriter) indirect(rv reflect.Value, depth int) error {
	for hops := 0; ; hops++ {
		if hops > maxDepth {
			return fmt.Errorf("%w: %w", ErrUnwritable, ErrTooDeep)
		}
		if encryptable(rv.Type()) {
			return unwritable("%s implements Encryptable, which has no storage form", rv.Type())
		}
		if rv.IsNil() {
			w.buf = append(w.buf, tagNull)
			return nil
		}
		elem := rv.Elem()
		if rv.Kind() == reflect.Pointer && startsOptional(elem) {
			w.buf = append(w.buf, StorageSome)
			return w.reflect(elem, depth+1)
		}
		if k := elem.Kind(); k != reflect.Pointer && k != reflect.Interface {
			return w.reflect(elem, depth)
		}
		rv = elem
	}
}

// startsOptional reports whether the bytes written for rv start with null or
// [StorageSome]. Such a value is a nil pointer, a nil interface, a [Some],
// or a pointer or interface to one of those. A pointer to such a value is
// written with StorageSome first. Otherwise a reader would treat the null or
// the tag as belonging to the outer pointer. The value would then read back
// with one level of pointer missing.
//
// The loop stops after maxDepth+2 steps. A chain of pointers longer than a
// blob can nest, such as a cycle, is refused when it is written. This
// function therefore does not follow such a chain further.
func startsOptional(rv reflect.Value) bool {
	for range maxDepth + 2 {
		switch rv.Kind() {
		case reflect.Pointer, reflect.Interface:
			if rv.IsNil() {
				return true
			}
			rv = rv.Elem()
		default:
			return rv.Type() == someType
		}
	}
	return false
}

// byteArray reports whether t is a [N]byte type that is written as bytes. A
// UUID is one. Int128 and Uint128 are [16]byte types too. The codec writes
// those two as integers, so the result for them is false.
func byteArray(t reflect.Type) bool {
	t = internalType(t)
	return t.Kind() == reflect.Array && t.Elem().Kind() == reflect.Uint8 && t != int128Type && t != uint128Type
}

func arrayBytes(rv reflect.Value) []byte {
	b := make([]byte, rv.Len())
	reflect.Copy(reflect.ValueOf(b), rv)
	return b
}

// encryptable reports whether t, or a pointer to t, implements Encryptable.
// The fields of such a type are not its value, so reflection must not write
// them.
func encryptable(t reflect.Type) bool {
	return implementsEncryptable(t) || implementsEncryptable(reflect.PointerTo(t))
}

// marshalText calls the MarshalText method of rv, if the type of rv has one.
// The second result reports whether the type has one. When the method has a
// pointer receiver, marshalText calls it on a pointer to a copy of rv.
func marshalText(rv reflect.Value) ([]byte, bool, error) {
	if rv.Type().Implements(textMarshalerType) && rv.CanInterface() {
		text, err := rv.Interface().(encoding.TextMarshaler).MarshalText()
		return text, true, err
	}
	if reflect.PointerTo(rv.Type()).Implements(textMarshalerType) {
		p := reflect.New(rv.Type())
		p.Elem().Set(rv)
		text, err := p.Interface().(encoding.TextMarshaler).MarshalText()
		return text, true, err
	}
	return nil, false, nil
}

func (w *storageWriter) text(s []byte) error {
	if !utf8.Valid(s) {
		return unwritable("a string is not valid UTF-8")
	}
	w.buf = append(w.buf, tagString)
	buf, err := appendChunk(w.buf, s)
	if err != nil {
		return unwritable("a string is too long")
	}
	w.buf = buf
	return nil
}

func (w *storageWriter) bytes(b []byte) error {
	w.buf = append(w.buf, tagBytes)
	buf, err := appendChunk(w.buf, b)
	if err != nil {
		return unwritable("bytes are too long")
	}
	w.buf = buf
	return nil
}

// open writes the tag of a container and four zero bytes for its count. The
// function returns the position of those bytes, and close writes the count
// there.
func (w *storageWriter) open(tag byte) int {
	w.buf = append(w.buf, tag, 0, 0, 0, 0)
	return len(w.buf) - 4
}

func (w *storageWriter) close(at, count int) error {
	if uint64(count) > maxUint32 {
		return unwritable("a container has too many entries")
	}
	binary.LittleEndian.PutUint32(w.buf[at:], uint32(count))
	return nil
}

func (w *storageWriter) array(rv reflect.Value, depth int) error {
	at := w.open(tagArray)
	for i := range rv.Len() {
		if err := w.reflect(rv.Index(i), depth+1); err != nil {
			return err
		}
	}
	return w.close(at, rv.Len())
}

func (w *storageWriter) object(o Object, depth int) error {
	at := w.open(tagObject)
	seen := make(map[string]struct{}, len(o))
	for _, f := range o {
		if err := w.field(f.Key, seen); err != nil {
			return err
		}
		if err := w.any(f.Value, depth+1); err != nil {
			return err
		}
	}
	return w.close(at, len(o))
}

// field writes one key of an object. The function refuses a key that the
// object already has.
func (w *storageWriter) field(key string, seen map[string]struct{}) error {
	if _, dup := seen[key]; dup {
		return unwritable("a key is repeated")
	}
	seen[key] = struct{}{}
	if !utf8.ValidString(key) {
		return unwritable("a key is not valid UTF-8")
	}
	buf, err := appendChunk(w.buf, []byte(key))
	if err != nil {
		return unwritable("a key is too long")
	}
	w.buf = buf
	return nil
}

func (w *storageWriter) goStruct(rv reflect.Value, depth int) error {
	at := w.open(tagObject)
	seen := make(map[string]struct{})
	fields, err := structFields(rv.Type())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnwritable, err)
	}
	written, unexported := 0, 0
	for _, f := range fields {
		if f.unexported {
			unexported++
			continue
		}
		if err := w.field(f.name, seen); err != nil {
			return err
		}
		if err := w.reflect(rv.Field(f.index), depth+1); err != nil {
			return err
		}
		written++
	}
	// The transport encoding has the same rule. A struct with only
	// unexported fields would be stored as an empty object. An example is
	// time.Time, if it had no MarshalText. The value would be lost, with no
	// error when it is written or read.
	if written == 0 && unexported > 0 {
		return unwritable("struct %s has no exported fields", rv.Type())
	}
	return w.close(at, written)
}

// storageField describes one field of a struct, with the name that a blob
// uses for it.
type storageField struct {
	name       string
	index      int
	unexported bool
	// defaulted is true for a field that reads as its zero value when a blob
	// does not have it.
	defaulted bool
}

// structFields returns the fields of t, in the order t declares them. Each
// field has the name from its `vc` tag, or its own name. A field with a
// `vc:"-"` tag is left out.
//
// A tag is a name, then options after commas, as in `vc:"age,default"`.
// Write `vc:",default"` to keep the field's own name. The only option is
// `default`. Any other option is refused, so a misspelt option is not
// ignored without an error. The transport encoding names fields in the same
// way.
func structFields(t reflect.Type) ([]storageField, error) {
	fields := make([]storageField, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			fields = append(fields, storageField{index: i, unexported: true})
			continue
		}
		field := storageField{name: f.Name, index: i}
		if tag, ok := f.Tag.Lookup("vc"); ok {
			if tag == "-" {
				continue
			}
			name, options, _ := strings.Cut(tag, ",")
			if name != "" {
				field.name = name
			}
			for options != "" {
				var option string
				option, options, _ = strings.Cut(options, ",")
				switch option {
				case "default":
					field.defaulted = true
				case "":
				default:
					return nil, fmt.Errorf("frame: field %s of %s has an unknown vc tag option %q", f.Name, t, option)
				}
			}
		}
		fields = append(fields, field)
	}
	return fields, nil
}

// mapKey is a map key: the node that is written for it, and an id that
// decides which keys are equal:
//
//   - Two integers are the same key when their values are equal, whatever
//     their widths. So 1 as a uint8 and 1 as an int64 are one key.
//   - Two text keys are the same when their bytes are equal. The same rule
//     applies to two bytes keys.
//   - A text key never equals a bytes key or an integer.
//
// The id also gives the order in which keys are written. Integers come
// first, then text, then bytes. The order of integers is by value. The order
// of text and of bytes is by their bytes.
type mapKey struct {
	node []byte
	id   keyID
}

// keyKind is the kind of a map key. The constants are in the order that keys
// of different kinds are written in.
type keyKind byte

const (
	keyInteger keyKind = iota
	keyText
	keyBytes
)

type keyID struct {
	kind keyKind
	// For an integer: the sign, and the 128-bit word in two's complement.
	negative bool
	hi, lo   uint64
	// For text or bytes: the bytes.
	s string
}

func compareKeys(a, b keyID) int {
	if c := cmp.Compare(a.kind, b.kind); c != 0 {
		return c
	}
	if a.negative != b.negative {
		if a.negative {
			return -1
		}
		return 1
	}
	return cmp.Or(cmp.Compare(a.hi, b.hi), cmp.Compare(a.lo, b.lo), cmp.Compare(a.s, b.s))
}

// wideKey returns the keyID of a 128-bit integer. The word argument is the
// integer in little-endian byte order.
func wideKey(word []byte, signed bool) keyID {
	return keyID{
		lo:       binary.LittleEndian.Uint64(word),
		hi:       binary.LittleEndian.Uint64(word[8:]),
		negative: signed && word[15]&0x80 != 0,
	}
}

// decodedKeyID returns the keyID of a key that the reader decoded. Such a
// key is a Go integer, an Int128, a Uint128, a string, or bytes.
func decodedKeyID(k any) (keyID, bool) {
	switch x := internal(k).(type) {
	case int8:
		return signedKey(int64(x)), true
	case int16:
		return signedKey(int64(x)), true
	case int32:
		return signedKey(int64(x)), true
	case int64:
		return signedKey(x), true
	case uint8:
		return keyID{lo: uint64(x)}, true
	case uint16:
		return keyID{lo: uint64(x)}, true
	case uint32:
		return keyID{lo: uint64(x)}, true
	case uint64:
		return keyID{lo: x}, true
	case Int128:
		return wideKey(x[:], true), true
	case Uint128:
		return wideKey(x[:], false), true
	case string:
		return keyID{kind: keyText, s: x}, true
	case []byte:
		return keyID{kind: keyBytes, s: string(x)}, true
	}
	return keyID{}, false
}

func signedKey(v int64) keyID {
	id := keyID{negative: v < 0, lo: uint64(v)}
	if id.negative {
		id.hi = math.MaxUint64
	}
	return id
}

// keyOf returns the node and the id for the map key k.
func keyOf(k any) (mapKey, error) {
	rv := reflect.ValueOf(k)
	if !rv.IsValid() {
		return mapKey{}, unwritable("a map key must be an integer, text or bytes")
	}
	// A nil pointer has no value to write. If its type has a MarshalText
	// method, that method would be called on nil.
	if (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && rv.IsNil() {
		return mapKey{}, unwritable("a map key must be an integer, text or bytes, not a nil %s", rv.Type())
	}
	w := &storageWriter{}
	var id keyID
	rv = internalValue(rv)
	switch t := rv.Type(); {
	case t == int128Type || t == uint128Type:
		b := arrayBytes(rv)
		signed := t == int128Type
		id = wideKey(b, signed)
		tag := byte(tagUint128)
		if signed {
			tag = tagInt128
		}
		w.buf = append(append(w.buf, tag), b...)
	case byteArray(t):
		b := arrayBytes(rv)
		id = keyID{kind: keyBytes, s: string(b)}
		_ = w.bytes(b)
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8:
		id = keyID{kind: keyBytes, s: string(rv.Bytes())}
		_ = w.bytes(rv.Bytes())
	default:
		if text, ok, err := marshalText(rv); ok {
			if err != nil {
				return mapKey{}, unwritable("the MarshalText method of the map key type %s returned an error", t)
			}
			id = keyID{kind: keyText, s: string(text)}
			if err := w.text(text); err != nil {
				return mapKey{}, err
			}
			break
		}
		switch t.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			id = signedKey(rv.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			id = keyID{lo: rv.Uint()}
		case reflect.String:
			id = keyID{kind: keyText, s: rv.String()}
			if err := w.text([]byte(rv.String())); err != nil {
				return mapKey{}, err
			}
			return mapKey{node: w.buf, id: id}, nil
		default:
			return mapKey{}, unwritable("a map key must be an integer, text or bytes, not %s", t)
		}
		if err := w.reflect(rv, 0); err != nil {
			return mapKey{}, err
		}
	}
	return mapKey{node: w.buf, id: id}, nil
}

func (w *storageWriter) goMap(rv reflect.Value, depth int) error {
	keys := make([]mapKey, 0, rv.Len())
	values := make(map[keyID]reflect.Value, rv.Len())
	for it := rv.MapRange(); it.Next(); {
		key, err := keyOf(interfaceOf(it.Key()))
		if err != nil {
			return err
		}
		if _, dup := values[key.id]; dup {
			// Two Go keys can be written as the same key. An example is two
			// values that a TextMarshaler writes as the same text.
			return unwritable("a key is repeated")
		}
		keys = append(keys, key)
		values[key.id] = it.Value()
	}
	// Go iterates over a map in a random order. Sorted keys give equal maps
	// equal blobs.
	slices.SortFunc(keys, func(a, b mapKey) int { return compareKeys(a.id, b.id) })
	at := w.open(StorageMap)
	for _, key := range keys {
		w.buf = append(w.buf, key.node...)
		if err := w.reflect(values[key.id], depth+1); err != nil {
			return err
		}
	}
	return w.close(at, len(keys))
}

func (w *storageWriter) entries(entries StorageEntries, depth int) error {
	at := w.open(StorageMap)
	seen := make(map[keyID]struct{}, len(entries))
	for _, e := range entries {
		key, err := keyOf(e.Key)
		if err != nil {
			return err
		}
		if _, dup := seen[key.id]; dup {
			return unwritable("a key is repeated")
		}
		seen[key.id] = struct{}{}
		w.buf = append(w.buf, key.node...)
		if err := w.any(e.Value, depth+1); err != nil {
			return err
		}
	}
	return w.close(at, len(entries))
}
