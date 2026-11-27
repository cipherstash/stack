package vcffi

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

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The storage profile, version 1: a value as one versioned blob, for bytes
// that are kept. It is the Go side of the Rust module
// vitaminc_aead_frame::storage, specified in
// packages/aead-frame/STORAGE.md and pinned by the golden corpus in
// packages/aead-frame/testdata/storage-v1.json. Unlike the rest of this
// package, which is transport, the bytes [MarshalStorage] writes and
// [UnmarshalStorage] reads are a compatibility commitment, shared with Rust.

// StorageVersion is the version this package writes, and the only one it
// reads.
const StorageVersion = 1

// StorageSome marks a present optional value: StorageSome, then the value.
// Rust writes it for every Some. Go writes it only for a pointer whose
// target is itself written as null, where leaving it out would read back as
// nil: a bare value reads as present into a pointer or a Rust Option, and as
// itself into a plain field, so a Go pointer is read alike in both
// languages, whatever the other side declares.
const StorageSome = 0xF5

// StorageMap starts a map whose keys are nodes: StorageMap, a u32 count,
// then a key and a value for each entry. A Go map is one; a struct is an
// object.
const StorageMap = 0xF6

// StorageHeader starts every blob: "VCS", then [StorageVersion].
var StorageHeader = [4]byte{'V', 'C', 'S', StorageVersion}

// The classes of a storage refusal, the Go side of Rust's
// storage::ErrorKind. Match them with errors.Is. A blob that breaks a rule
// of its version is [ErrMalformed], as transport bytes are.
var (
	// ErrNotABlob: shorter than the header, or not starting with "VCS".
	ErrNotABlob = errors.New("vcffi: not a storage blob")
	// ErrUnsupportedVersion: a blob of a version this package does not
	// read. A later release may: the reader needs upgrading, and the blob
	// is not corrupt.
	ErrUnsupportedVersion = errors.New("vcffi: an unsupported storage version")
	// ErrMismatch: a well-formed blob whose value the destination does not
	// take: a string where a number was expected, a missing field.
	ErrMismatch = errors.New("vcffi: the stored value does not fit the destination")
	// ErrUnwritable: a value that cannot be written as a blob: nested too
	// deep, a map key that is not an integer, text or bytes, a repeated
	// key, a kind with no storage form.
	ErrUnwritable = errors.New("vcffi: the value cannot be written as a storage blob")
)

// Some is a present optional value, as a blob holds it, for a value read
// into an `any`. A pointer is the usual way to write one.
type Some struct {
	V any
}

// StorageEntries is a map as a blob holds it, for a value read into an
// `any`: its entries in the order they were written, each key an integer,
// a string or []byte. Written, it is a map in that order.
type StorageEntries []StorageEntry

// StorageEntry is one entry of [StorageEntries].
type StorageEntry struct {
	Key   any
	Value any
}

func unwritable(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnwritable}, args...)...)
}

// MarshalStorage writes v as a version 1 blob:
//
//   - nil, a nil interface         → null;
//   - bool                         → bool;
//   - int8, int16, int32, int64    → that width; int → int64;
//   - uint8 … uint64               → that width; uint, uintptr → uint64;
//   - vcvalue.Int128, Uint128      → the 128-bit widths;
//   - float32, float64             → that width, by its bits;
//   - string                       → text (valid UTF-8 only);
//   - []byte, [N]byte              → bytes (so a UUID is its 16 bytes);
//   - an encoding.TextMarshaler    → text (time.Time as RFC 3339);
//   - slices, arrays               → array; a nil slice is an empty one;
//   - map[K]V                      → map, keys sorted: integers by value,
//     text and bytes by their bytes, as a Rust BTreeMap orders them; K is
//     an integer, a string, a byte array or a TextMarshaler;
//   - structs                      → object, by field name, honoring
//     `vc:"name"` tags (`vc:"-"` skips a field), in declaration order; a
//     `vc:"name,default"` field reads as its zero value when a blob does
//     not have it;
//   - pointers                     → nil is null, and a non-nil pointer is
//     what it points at, as encoding/json writes it; a pointer to a value
//     written starting with null or [StorageSome] (a nil pointer or
//     interface, [Some], or a pointer to one) is [StorageSome] then that
//     value, so every level reads back;
//   - [Some], [StorageEntries], vcvalue.Object and []any → as they read.
//
// The transport's Encryptable, passthrough (vcvalue.Plain) and logical
// types (vcvalue.Date, Timestamp, Decimal, Tagged, TypedNull) have no
// storage form, and are refused.
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

// The model's own types, which [storageWriter.model] writes. Int128 and
// Uint128 are [16]byte too, so [byteArray] also leaves them out, for a
// value model cannot box and for the reader.
var (
	int128Type    = reflect.TypeOf(vcvalue.Int128{})
	uint128Type   = reflect.TypeOf(vcvalue.Uint128{})
	someType      = reflect.TypeOf(Some{})
	objectType    = reflect.TypeOf(vcvalue.Object{})
	entriesType   = reflect.TypeOf(StorageEntries{})
	plainType     = reflect.TypeOf(vcvalue.Plain{})
	dateType      = reflect.TypeOf(vcvalue.Date{})
	timestampType = reflect.TypeOf(vcvalue.Timestamp{})
	decimalType   = reflect.TypeOf(vcvalue.Decimal{})
	taggedType    = reflect.TypeOf(vcvalue.Tagged{})
	typedNullType = reflect.TypeOf(vcvalue.TypedNull{})
)

// model writes rv if its type is one of the model's own, which have a form
// of their own rather than the one reflection would give them, and reports
// whether it was. Only those types are boxed to be written.
func (w *storageWriter) model(rv reflect.Value, depth int) (bool, error) {
	if !rv.CanInterface() {
		return false, nil
	}
	switch rv.Type() {
	case someType:
		w.buf = append(w.buf, StorageSome)
		return true, w.any(rv.Interface().(Some).V, depth+1)
	case objectType:
		return true, w.object(rv.Interface().(vcvalue.Object), depth)
	case entriesType:
		return true, w.entries(rv.Interface().(StorageEntries), depth)
	case int128Type:
		x := rv.Interface().(vcvalue.Int128)
		w.buf = append(append(w.buf, tagInt128), x[:]...)
		return true, nil
	case uint128Type:
		x := rv.Interface().(vcvalue.Uint128)
		w.buf = append(append(w.buf, tagUint128), x[:]...)
		return true, nil
	case plainType, dateType, timestampType, decimalType, taggedType, typedNullType:
		return true, unwritable("%s has no storage form", rv.Type())
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
	// Checked by type, before a nil pointer is written as null, so a field
	// of an Encryptable type is refused whether or not it is set.
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
			return unwritable("%s refused to write itself as text", rv.Type())
		}
		return w.text(text)
	}
	if k, ok := numericKinds[rv.Kind()]; ok {
		// The transport's numeric table writes each kind at the same width
		// a blob does: only the framing differs, and there is none here.
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

// indirect writes what the pointer or interface rv holds: null if it is
// nil, and otherwise what it points at, marked if that starts with null or
// a marker (see [startsOptional]). The marker is a node, and costs a level
// of depth as a reader counts it; a pointer or interface that writes
// nothing of its own costs none, since the blob is no deeper for it. A run
// of those is bounded on its own, so a cycle (p = &p) is refused rather
// than followed forever.
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

// startsOptional reports whether rv is written starting with null or
// [StorageSome]: a nil pointer or interface, [Some], or a pointer or
// interface to one of those. A pointer to such a value is marked, or a
// reader would take that null or marker for the pointer's own, and the
// value would read back one level shorter. A run of pointers longer than a
// blob may nest, a cycle say, is refused when it is written, so it is not
// followed further here.
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

// byteArray reports whether t is [N]byte, a UUID say, written as bytes.
// Int128 and Uint128 are [16]byte too, and are integers.
func byteArray(t reflect.Type) bool {
	return t.Kind() == reflect.Array && t.Elem().Kind() == reflect.Uint8 && t != int128Type && t != uint128Type
}

func arrayBytes(rv reflect.Value) []byte {
	b := make([]byte, rv.Len())
	reflect.Copy(reflect.ValueOf(b), rv)
	return b
}

// encryptable reports whether t, or a pointer to it, implements
// Encryptable: its fields are not its value, so reflection must not write
// them.
func encryptable(t reflect.Type) bool {
	return t.Implements(encryptableType) || reflect.PointerTo(t).Implements(encryptableType)
}

// marshalText is rv's MarshalText, if its type has one, through a pointer
// to a copy when the method needs one.
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

// open writes a container's tag and a count to be patched by close.
func (w *storageWriter) open(tag byte) int {
	w.buf = append(w.buf, tag, 0, 0, 0, 0)
	return len(w.buf) - 4
}

func (w *storageWriter) close(at, count int) error {
	if uint64(count) > maxUint32 {
		return unwritable("a container holds too many entries")
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

func (w *storageWriter) object(o vcvalue.Object, depth int) error {
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

// field writes an object's key, refusing one already written.
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
	// As in the transport: a struct of only unexported fields (time.Time
	// without its MarshalText, say) would be stored as an empty object, and
	// its value lost with no error at either end.
	if written == 0 && unexported > 0 {
		return unwritable("struct %s has no exported fields", rv.Type())
	}
	return w.close(at, written)
}

// storageField is a struct field as a blob names it.
type storageField struct {
	name       string
	index      int
	unexported bool
	// defaulted fields read as their zero value when a blob lacks them.
	defaulted bool
}

// structFields are t's fields in declaration order, named by their `vc`
// tags, without the ones a `vc:"-"` tag skips. A tag is a name, then
// options after commas: `vc:"age,default"`, or `vc:",default"` to keep the
// field's own name. `default` is the only option; any other is refused, so
// a misspelt one is not quietly ignored. The transport names fields the
// same way.
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
					return nil, fmt.Errorf("vcffi: field %s of %s has an unknown vc tag option %q", f.Name, t, option)
				}
			}
		}
		fields = append(fields, field)
	}
	return fields, nil
}

// mapKey is a map key written as a node, and what makes two keys the same:
// integers of equal value, whatever their widths, so 1 as a uint8 and 1 as
// an int64 are one key; text and bytes by their bytes, never equal to each
// other or to an integer. Its order is the one keys are written in: by
// kind, integers by value, text and bytes by their bytes.
type mapKey struct {
	node []byte
	id   keyID
}

// keyKind is a map key's kind, in the order keys of different kinds are
// written in.
type keyKind byte

const (
	keyInteger keyKind = iota
	keyText
	keyBytes
)

type keyID struct {
	kind keyKind
	// An integer as its sign and its two's-complement 128-bit word.
	negative bool
	hi, lo   uint64
	// Text or bytes.
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

// wideKey is the keyID of a 128-bit integer, from its little-endian word.
func wideKey(word []byte, signed bool) keyID {
	return keyID{
		lo:       binary.LittleEndian.Uint64(word),
		hi:       binary.LittleEndian.Uint64(word[8:]),
		negative: signed && word[15]&0x80 != 0,
	}
}

// decodedKeyID is the keyID of a key as the reader decodes it: a Go
// integer, Int128 or Uint128, a string, or bytes.
func decodedKeyID(k any) (keyID, bool) {
	switch x := k.(type) {
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
	case vcvalue.Int128:
		return wideKey(x[:], true), true
	case vcvalue.Uint128:
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

// keyOf writes a map key as its node.
func keyOf(k any) (mapKey, error) {
	rv := reflect.ValueOf(k)
	if !rv.IsValid() {
		return mapKey{}, unwritable("a map key must be an integer, text or bytes")
	}
	// A nil pointer has no value to write; its type's MarshalText, if it
	// has one, would be called on nil.
	if (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && rv.IsNil() {
		return mapKey{}, unwritable("a map key must be an integer, text or bytes, not a nil %s", rv.Type())
	}
	w := &storageWriter{}
	var id keyID
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
				return mapKey{}, unwritable("a map key of type %s refused to write itself as text", t)
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
			// Two Go keys that write the same key: two texts a
			// TextMarshaler spells alike, say.
			return unwritable("a key is repeated")
		}
		keys = append(keys, key)
		values[key.id] = it.Value()
	}
	// Go map iteration is randomized; sorting makes equal maps equal blobs.
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
