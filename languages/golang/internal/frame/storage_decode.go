package vcffi

import (
	"encoding"
	"fmt"
	"math/big"
	"reflect"
	"strconv"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// UnmarshalStorage reads a version 1 blob into the value v points at.
//
// The whole blob is checked first, so a blob of another version, bytes
// that are not a blob, or a malformed body is refused before anything is
// set: [ErrNotABlob], [ErrUnsupportedVersion] or [ErrMalformed]. Then the
// value is read into v by its type, as Rust's serde reads it, which the
// corpus's `reads` rows pin:
//
//   - an integer reads into any integer type it fits; a float type reads a
//     float or an integer; an integer type never reads a float;
//   - a pointer reads null as nil, and any other value, marked present or
//     not, as a pointer to that value: a Rust Some and a Go pointer alike;
//   - a string reads only text, []byte and [N]byte only bytes (of length
//     N), a slice or an array only an array;
//   - a map reads a map or an object, each key read as a value of the key
//     type would be;
//   - a struct reads an object, or a map whose keys are all text; unknown
//     keys are ignored, and a missing field is refused unless it is a
//     pointer, which is left nil, or tagged `vc:"name,default"`, which is
//     left its zero value, as Rust's #[serde(default)] reads it;
//   - an encoding.TextUnmarshaler reads text;
//   - an `any` reads the value as the blob holds it: nil, bool, the integer
//     widths (vcvalue.Int128 and Uint128 for 128 bits), float32, float64,
//     string, []byte, []any, vcvalue.Object for an object,
//     [StorageEntries] for a map, and [Some] for an optional value.
//
// A value that does not fit is [ErrMismatch]. Its message names the kind
// found and where, never the value.
func UnmarshalStorage(blob []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("vcffi: UnmarshalStorage needs a non-nil pointer, not %T", v)
	}
	model, err := decodeStorage(blob)
	if err != nil {
		return err
	}
	return assign(model, rv.Elem(), "")
}

// decodeStorage reads a whole blob as the value it holds, refusing any blob
// a version 1 reader refuses.
func decodeStorage(blob []byte) (any, error) {
	if len(blob) < len(StorageHeader) || string(blob[:3]) != "VCS" {
		return nil, ErrNotABlob
	}
	if blob[3] != StorageVersion {
		return nil, ErrUnsupportedVersion
	}
	r := &reader{buf: blob[len(StorageHeader):]}
	v, err := storageNode(r, 0)
	if err != nil {
		return nil, err
	}
	if !r.finished() {
		return nil, ErrMalformed
	}
	return v, nil
}

// storageScalar reports whether tag starts a version 1 scalar.
func storageScalar(tag byte) bool {
	switch tag {
	case tagNull, tagFalse, tagTrue, tagFloat32, tagFloat64:
		return true
	}
	return storageKeyTag(tag)
}

// storageKeyTag reports whether tag may start a map's key.
func storageKeyTag(tag byte) bool {
	switch tag {
	case tagInt8, tagInt16, tagInt32, tagInt64, tagInt128,
		tagUint8, tagUint16, tagUint32, tagUint64, tagUint128, tagString, tagBytes:
		return true
	}
	return false
}

func storageNode(r *reader, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	switch tag {
	case StorageSome:
		inner, err := storageNode(r, depth+1)
		if err != nil {
			return nil, err
		}
		return Some{V: inner}, nil
	case tagArray:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, eagerCap(n))
		for range n {
			item, err := storageNode(r, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case tagObject:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		fields := make(vcvalue.Object, 0, eagerCap(n))
		seen := make(map[string]struct{}, eagerCap(n))
		for range n {
			key, err := r.str()
			if err != nil {
				return nil, err
			}
			if _, dup := seen[key]; dup {
				return nil, ErrMalformed
			}
			seen[key] = struct{}{}
			value, err := storageNode(r, depth+1)
			if err != nil {
				return nil, err
			}
			fields = append(fields, vcvalue.Field{Key: key, Value: value})
		}
		return fields, nil
	case StorageMap:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		entries := make(StorageEntries, 0, eagerCap(n))
		seen := make(map[keyID]struct{}, eagerCap(n))
		for range n {
			tag, err := r.byteTag()
			if err != nil {
				return nil, err
			}
			if !storageKeyTag(tag) {
				return nil, ErrMalformed
			}
			key, err := decodeTagged(r, tag, depth+1)
			if err != nil {
				return nil, err
			}
			id, ok := decodedKeyID(key)
			if !ok {
				return nil, ErrMalformed
			}
			if _, dup := seen[id]; dup {
				return nil, ErrMalformed
			}
			seen[id] = struct{}{}
			value, err := storageNode(r, depth+1)
			if err != nil {
				return nil, err
			}
			entries = append(entries, StorageEntry{Key: key, Value: value})
		}
		return entries, nil
	}
	if !storageScalar(tag) {
		return nil, ErrMalformed
	}
	return decodeTagged(r, tag, depth)
}

// =============================================================================
// Reading into a Go value
// =============================================================================

// kindOf names what a model value is, for a refusal: never the value.
func kindOf(m any) string {
	switch m.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case int8, int16, int32, int64, vcvalue.Int128, uint8, uint16, uint32, uint64, vcvalue.Uint128:
		return "an integer"
	case float32, float64:
		return "a float"
	case string:
		return "text"
	case []byte:
		return "bytes"
	case []any:
		return "an array"
	case vcvalue.Object, StorageEntries:
		return "an object"
	case Some:
		return "an optional value"
	}
	return "a value of another kind"
}

func mismatch(path, want string, found any) error {
	return fmt.Errorf("%w: %s: expected %s, found %s", ErrMismatch, orRoot(path), want, kindOf(found))
}

// integerOf is a model integer's value.
func integerOf(m any) (*big.Int, bool) {
	if small, ok := smallIntegerOf(m); ok {
		return big.NewInt(small), true
	}
	return wideIntegerOf(m)
}

// int128Of is v as the 16 little-endian bytes of a two's-complement word.
func int128Of(v *big.Int) [16]byte {
	word := new(big.Int).Set(v)
	if word.Sign() < 0 {
		word.Add(word, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	var out [16]byte
	b := word.FillBytes(make([]byte, 16))
	for i := range out {
		out[i] = b[15-i]
	}
	return out
}

var (
	minInt128  = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	maxInt128  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	maxUint128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
)

func assign(m any, rv reflect.Value, path string) error {
	switch rv.Kind() {
	case reflect.Interface:
		if m == nil {
			rv.SetZero()
			return nil
		}
		if mv := reflect.ValueOf(m); mv.Type().AssignableTo(rv.Type()) {
			rv.Set(mv)
			return nil
		}
		return mismatch(path, rv.Type().String(), m)
	case reflect.Pointer:
		switch x := m.(type) {
		case nil:
			rv.SetZero()
			return nil
		case Some:
			m = x.V
		}
		p := reflect.New(rv.Type().Elem())
		if err := assign(m, p.Elem(), path); err != nil {
			return err
		}
		rv.Set(p)
		return nil
	}
	if _, ok := m.(Some); ok {
		return mismatch(path, rv.Type().String(), m)
	}
	switch t := rv.Type(); {
	case t == int128Type || t == uint128Type:
		return assignInteger(m, rv, path)
	case byteArray(t):
		b, ok := m.([]byte)
		if !ok || len(b) != rv.Len() {
			return mismatch(path, fmt.Sprintf("%d bytes", rv.Len()), m)
		}
		reflect.Copy(rv, reflect.ValueOf(b))
		return nil
	case reflect.PointerTo(t).Implements(textUnmarshalerType) && rv.CanAddr():
		text, ok := m.(string)
		if !ok {
			return mismatch(path, "text", m)
		}
		if err := rv.Addr().Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(text)); err != nil {
			return fmt.Errorf("%w: %s: text %s does not take", ErrMismatch, orRoot(path), t)
		}
		return nil
	}
	switch rv.Kind() {
	case reflect.Bool:
		b, ok := m.(bool)
		if !ok {
			return mismatch(path, "a boolean", m)
		}
		rv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return assignInteger(m, rv, path)
	case reflect.Float32, reflect.Float64:
		return assignFloat(m, rv, path)
	case reflect.String:
		s, ok := m.(string)
		if !ok {
			return mismatch(path, "text", m)
		}
		rv.SetString(s)
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			b, ok := m.([]byte)
			if !ok {
				return mismatch(path, "bytes", m)
			}
			rv.SetBytes(append([]byte{}, b...))
			return nil
		}
		items, ok := m.([]any)
		if !ok {
			return mismatch(path, "an array", m)
		}
		s := reflect.MakeSlice(rv.Type(), len(items), len(items))
		for i, item := range items {
			if err := assign(item, s.Index(i), path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
		rv.Set(s)
	case reflect.Array:
		items, ok := m.([]any)
		if !ok || len(items) != rv.Len() {
			return mismatch(path, fmt.Sprintf("an array of %d", rv.Len()), m)
		}
		for i, item := range items {
			if err := assign(item, rv.Index(i), path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
	case reflect.Map:
		return assignMap(m, rv, path)
	case reflect.Struct:
		return assignStruct(m, rv, path)
	default:
		return fmt.Errorf("%w: %s: a %s cannot be read", ErrMismatch, orRoot(path), rv.Type())
	}
	return nil
}

func orRoot(path string) string {
	if path == "" {
		return "the value"
	}
	return path
}

func assignInteger(m any, rv reflect.Value, path string) error {
	v, ok := integerOf(m)
	if !ok {
		return mismatch(path, "an integer", m)
	}
	fits := false
	switch t := rv.Type(); {
	case t == int128Type:
		if fits = v.Cmp(minInt128) >= 0 && v.Cmp(maxInt128) <= 0; fits {
			rv.Set(reflect.ValueOf(vcvalue.Int128(int128Of(v))))
		}
	case t == uint128Type:
		if fits = v.Sign() >= 0 && v.Cmp(maxUint128) <= 0; fits {
			rv.Set(reflect.ValueOf(vcvalue.Uint128(int128Of(v))))
		}
	case rv.CanInt():
		if fits = v.IsInt64() && !rv.OverflowInt(v.Int64()); fits {
			rv.SetInt(v.Int64())
		}
	default:
		if fits = v.IsUint64() && !rv.OverflowUint(v.Uint64()); fits {
			rv.SetUint(v.Uint64())
		}
	}
	if !fits {
		return fmt.Errorf("%w: %s: an integer that does not fit %s", ErrMismatch, orRoot(path), rv.Type())
	}
	return nil
}

func assignFloat(m any, rv reflect.Value, path string) error {
	switch x := m.(type) {
	case float32:
		// Converted rather than widened, so a float32 keeps its bits
		// (reflect copies float32 to float32, Go issue 36400).
		rv.Set(reflect.ValueOf(x).Convert(rv.Type()))
		return nil
	case float64:
		rv.SetFloat(x)
		return nil
	}
	v, ok := integerOf(m)
	if !ok {
		return mismatch(path, "a float", m)
	}
	// Rounded once, to the destination's width, as Rust's `as` rounds.
	if rv.Kind() == reflect.Float32 {
		f, _ := new(big.Float).SetInt(v).Float32()
		rv.SetFloat(float64(f))
		return nil
	}
	f, _ := new(big.Float).SetInt(v).Float64()
	rv.SetFloat(f)
	return nil
}

// entriesOf is an object's or a map's entries, whichever m is.
func entriesOf(m any) (StorageEntries, bool) {
	switch x := m.(type) {
	case StorageEntries:
		return x, true
	case vcvalue.Object:
		entries := make(StorageEntries, len(x))
		for i, f := range x {
			entries[i] = StorageEntry{Key: f.Key, Value: f.Value}
		}
		return entries, true
	}
	return nil, false
}

func assignMap(m any, rv reflect.Value, path string) error {
	entries, ok := entriesOf(m)
	if !ok {
		return mismatch(path, "a map", m)
	}
	out := reflect.MakeMapWithSize(rv.Type(), len(entries))
	for i, e := range entries {
		at := path + "{" + strconv.Itoa(i) + "}"
		key := reflect.New(rv.Type().Key()).Elem()
		if err := assign(e.Key, key, at); err != nil {
			return err
		}
		// A bytes key read into an interface key is a []byte, which a Go
		// map cannot hash: SetMapIndex would panic.
		if !key.Comparable() {
			return mismatch(at, "a key a Go map can hold", e.Key)
		}
		value := reflect.New(rv.Type().Elem()).Elem()
		if err := assign(e.Value, value, at); err != nil {
			return err
		}
		out.SetMapIndex(key, value)
	}
	rv.Set(out)
	return nil
}

func assignStruct(m any, rv reflect.Value, path string) error {
	entries, ok := entriesOf(m)
	if !ok {
		return mismatch(path, "an object", m)
	}
	fields, err := structFields(rv.Type())
	if err != nil {
		return err
	}
	byName := make(map[string]int, len(fields))
	for i, f := range fields {
		if !f.unexported {
			byName[f.name] = i
		}
	}
	set := make([]bool, len(fields))
	for _, e := range entries {
		name, ok := e.Key.(string)
		if !ok {
			return mismatch(path, "a field name", e.Key)
		}
		i, known := byName[name]
		if !known {
			continue
		}
		set[i] = true
		if err := assign(e.Value, rv.Field(fields[i].index), path+"."+name); err != nil {
			return err
		}
	}
	for i, f := range fields {
		if set[i] || f.unexported {
			continue
		}
		field := rv.Field(f.index)
		if field.Kind() != reflect.Pointer && !f.defaulted {
			return fmt.Errorf("%w: %s: missing field %q", ErrMismatch, orRoot(path), f.name)
		}
		field.SetZero()
	}
	return nil
}
