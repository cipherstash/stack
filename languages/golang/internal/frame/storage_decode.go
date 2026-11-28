package frame

import (
	"encoding"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
)

// UnmarshalStorage reads a version 1 blob into the value that v points at.
//
// UnmarshalStorage checks the whole blob before it sets anything. The
// function returns one of three errors for a blob it cannot read:
//
//   - [ErrNotABlob] for bytes that are not a blob
//   - [ErrUnsupportedVersion] for a blob of another version
//   - [ErrMalformed] for a blob with a malformed body
//
// UnmarshalStorage then reads the value into v, by the type of v, as serde
// reads it in Rust. The `reads` rows of the storage corpus test these rules:
//
//   - An integer type reads any integer that fits it. A float type reads a
//     float or an integer. An integer type never reads a float.
//   - A pointer reads null as nil. A pointer reads any other value as a
//     pointer to that value. The value can have the [StorageSome] tag or
//     not. A Rust Some and a Go pointer therefore read the same way.
//   - A string reads only text. A []byte reads only bytes. A [N]byte reads
//     only bytes of length N. A slice or an array reads only an array.
//   - A map reads a map or an object. Each key is read as a value of the key
//     type would be.
//   - A struct reads an object, or a map whose keys are all text. Unknown
//     keys are ignored. A missing field is refused, with two exceptions. A
//     missing pointer field is left nil. A missing field tagged
//     `vc:"name,default"` is left as its zero value, as #[serde(default)]
//     does in Rust.
//   - A type that implements encoding.TextUnmarshaler reads text.
//   - An `any` reads the value as the blob stores it. A scalar reads as nil,
//     a bool, an integer of the stored width, a float32, a float64, a
//     string, or a []byte. A 128-bit integer reads as an Int128 or a
//     Uint128. An array reads as a []any, an object as an Object, a map as a
//     [StorageEntries], and an optional value as a [Some].
//
// UnmarshalStorage returns [ErrMismatch] for a value that does not fit. The
// message names the kind of value found and its position, and never the
// value itself.
func UnmarshalStorage(blob []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("frame: UnmarshalStorage needs a non-nil pointer, not %T", v)
	}
	model, err := decodeStorage(blob)
	if err != nil {
		return err
	}
	return assign(model, rv.Elem(), "")
}

// decodeStorage reads a whole blob and returns the value in it. The function
// refuses every blob that a version 1 reader must refuse.
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

// storageKeyTag reports whether tag can start the key of a map.
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
		fields := make(Object, 0, eagerCap(n))
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
			fields = append(fields, Field{Key: key, Value: value})
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

// kindOf returns the name of the kind of m, for an error message. The name
// never contains the value.
func kindOf(m any) string {
	switch internal(m).(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case int8, int16, int32, int64, Int128, uint8, uint16, uint32, uint64, Uint128:
		return "an integer"
	case float32, float64:
		return "a float"
	case string:
		return "text"
	case []byte:
		return "bytes"
	case []any:
		return "an array"
	case Object, StorageEntries:
		return "an object"
	case Some:
		return "an optional value"
	}
	return "a value of another kind"
}

func mismatch(path, want string, found any) error {
	return fmt.Errorf("%w: %s: expected %s, found %s", ErrMismatch, orRoot(path), want, kindOf(found))
}

// integerOf returns the value of m, when m is a decoded integer.
func integerOf(m any) (*big.Int, bool) {
	if small, ok := smallIntegerOf(m); ok {
		return big.NewInt(small), true
	}
	return wideIntegerOf(m)
}

// int128Of returns v as a 128-bit word in two's complement: 16 bytes in
// little-endian order.
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
	case internalType(t) == int128Type || internalType(t) == uint128Type:
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
	switch t := internalType(rv.Type()); {
	case t == int128Type:
		if fits = v.Cmp(minInt128) >= 0 && v.Cmp(maxInt128) <= 0; fits {
			rv.Set(reflect.ValueOf(Int128(int128Of(v))).Convert(rv.Type()))
		}
	case t == uint128Type:
		if fits = v.Sign() >= 0 && v.Cmp(maxUint128) <= 0; fits {
			rv.Set(reflect.ValueOf(Uint128(int128Of(v))).Convert(rv.Type()))
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
		// The value is converted, not widened, so a float32 keeps its bits.
		// The reflect package copies a float32 to a float32. See Go issue
		// 36400.
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
	// The integer is rounded once, to the width of the destination, as the
	// `as` operator rounds in Rust.
	if rv.Kind() == reflect.Float32 {
		f, _ := new(big.Float).SetInt(v).Float32()
		rv.SetFloat(float64(f))
		return nil
	}
	f, _ := new(big.Float).SetInt(v).Float64()
	rv.SetFloat(f)
	return nil
}

// entriesOf returns the entries of m, when m is an object or a map.
func entriesOf(m any) (StorageEntries, bool) {
	switch x := m.(type) {
	case StorageEntries:
		return x, true
	case Object:
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
		// A bytes key that is read into an interface key is a []byte. A Go
		// map cannot hash a []byte, so SetMapIndex would panic.
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
