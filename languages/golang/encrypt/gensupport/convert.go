package gensupport

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// convert writes an opened sealed value into out, a pointer to the Go type
// the struct declares. The engine returns a value at the field's declared
// kind — int32, int64, uint32, uint64, float32, float64, string, []byte,
// bool, or a vcvalue.Object for a composite — and the struct's type is in
// the same family, narrower at most. A value outside the target's range, or
// of another family, is an error.
//
// An error names types and positions, never the value: the value is
// decrypted plaintext, and an error is what a program logs.
//
// The switch names the built-in types; a type defined over one (type Status
// string, time.Duration), or a slice or map of any readable type, is read
// through its underlying type by [convertVia], the one place this package
// uses reflection. Generated code uses none: it hands Get the field's type
// and the engine's value, and reads a value back.
func convert(v any, out any) error {
	// A JSON number — what an opaque document carries — widens to its
	// family's widest type, and the family's range check applies below.
	if n, ok := v.(json.Number); ok {
		var err error
		if v, err = widenNumber(n, out); err != nil {
			return err
		}
	}
	// A nil slice or map comes back as nil: the zero value it was.
	if v == nil {
		switch out.(type) {
		case *[]byte, *[]any, *[]string, *[]int64, *[]int32, *[]uint32, *[]uint64, *[]float64, *[]bool, *[][]byte, *Values, *map[string]any, *any:
			return nil
		}
		return fmt.Errorf("opened as nothing, and %T holds a value", out)
	}
	switch out := out.(type) {
	case *string:
		s, ok := v.(string)
		if !ok {
			return mismatch(v, *out)
		}
		*out = s
	case *[]byte:
		b, ok := v.([]byte)
		if !ok {
			return mismatch(v, *out)
		}
		*out = append([]byte(nil), b...)
	case *bool:
		b, ok := v.(bool)
		if !ok {
			return mismatch(v, *out)
		}
		*out = b
	case *int:
		return setInt(v, out, math.MinInt, math.MaxInt)
	case *int8:
		return setInt(v, out, math.MinInt8, math.MaxInt8)
	case *int16:
		return setInt(v, out, math.MinInt16, math.MaxInt16)
	case *int32:
		return setInt(v, out, math.MinInt32, math.MaxInt32)
	case *int64:
		return setInt(v, out, math.MinInt64, math.MaxInt64)
	case *uint:
		return setUint(v, out, math.MaxUint)
	case *uint8:
		return setUint(v, out, math.MaxUint8)
	case *uint16:
		return setUint(v, out, math.MaxUint16)
	case *uint32:
		return setUint(v, out, math.MaxUint32)
	case *uint64:
		return setUint(v, out, math.MaxUint64)
	case *float32:
		switch f := v.(type) {
		case float32:
			*out = f
		case float64:
			if f != 0 && !math.IsInf(f, 0) && !math.IsNaN(f) && (math.Abs(f) > math.MaxFloat32 || math.Abs(f) < math.SmallestNonzeroFloat32) {
				return outOfRange(*out)
			}
			*out = float32(f)
		default:
			return mismatch(v, *out)
		}
	case *float64:
		switch f := v.(type) {
		case float32:
			*out = float64(f)
		case float64:
			*out = f
		default:
			return mismatch(v, *out)
		}
	case *Values:
		vals, err := valuesOf(v)
		if err != nil {
			return err
		}
		*out = vals
	case *map[string]any:
		vals, err := valuesOf(v)
		if err != nil {
			return err
		}
		*out = map[string]any(vals)
	case *[]any:
		items, ok := v.([]any)
		if !ok {
			return mismatch(v, *out)
		}
		*out = append([]any(nil), items...)
	case *[]string:
		return setSlice(v, out)
	case *[]int64:
		return setSlice(v, out)
	case *[]int32:
		return setSlice(v, out)
	case *[]uint32:
		return setSlice(v, out)
	case *[]uint64:
		return setSlice(v, out)
	case *[]float64:
		return setSlice(v, out)
	case *[]bool:
		return setSlice(v, out)
	case *[][]byte:
		return setSlice(v, out)
	case *any:
		*out = v
	default:
		return convertVia(v, out)
	}
	return nil
}

// convertVia reads a value into a type the switch in convert does not name:
// a type defined over a scalar is read as its underlying type and converted;
// a slice or array element by element; a map with string keys entry by
// entry, each value through convert. Anything else is a mismatch.
func convertVia(v any, out any) error {
	target := reflect.ValueOf(out)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return fmt.Errorf("the opened value is a %T, which %T cannot hold", v, out)
	}
	elem := target.Elem()
	t := elem.Type()
	switch t.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		// A defined type: read the underlying type, then convert.
		under := reflect.New(underlying(t))
		if err := convert(v, under.Interface()); err != nil {
			return err
		}
		elem.Set(under.Elem().Convert(t))
		return nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			var b []byte
			if err := convert(v, &b); err != nil {
				return err
			}
			elem.Set(reflect.ValueOf(b).Convert(t))
			return nil
		}
		items, ok := v.([]any)
		if !ok {
			return fmt.Errorf("opened as %T, not %s", v, t)
		}
		result := reflect.MakeSlice(t, len(items), len(items))
		for i, item := range items {
			if err := convert(item, result.Index(i).Addr().Interface()); err != nil {
				return fmt.Errorf("element %d: %w", i, err)
			}
		}
		elem.Set(result)
		return nil
	case reflect.Array:
		items, ok := v.([]any)
		if !ok || len(items) != t.Len() {
			return fmt.Errorf("opened as %T with %d elements, not %s", v, len(items), t)
		}
		result := reflect.New(t).Elem()
		for i, item := range items {
			if err := convert(item, result.Index(i).Addr().Interface()); err != nil {
				return fmt.Errorf("element %d: %w", i, err)
			}
		}
		elem.Set(result)
		return nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("%s has a key that is not a string", t)
		}
		vals, err := valuesOf(v)
		if err != nil {
			return err
		}
		result := reflect.MakeMapWithSize(t, len(vals))
		for key, item := range vals {
			slot := reflect.New(t.Elem())
			if err := convert(item, slot.Interface()); err != nil {
				return fmt.Errorf("an entry of %s: %w", t, err)
			}
			result.SetMapIndex(reflect.ValueOf(key).Convert(t.Key()), slot.Elem())
		}
		elem.Set(result)
		return nil
	}
	return fmt.Errorf("the opened value is a %T, which this field's type %s cannot hold", v, t)
}

// underlying is the built-in type a defined scalar type is declared over.
func underlying(t reflect.Type) reflect.Type {
	switch t.Kind() {
	case reflect.Bool:
		return reflect.TypeFor[bool]()
	case reflect.String:
		return reflect.TypeFor[string]()
	case reflect.Int:
		return reflect.TypeFor[int]()
	case reflect.Int8:
		return reflect.TypeFor[int8]()
	case reflect.Int16:
		return reflect.TypeFor[int16]()
	case reflect.Int32:
		return reflect.TypeFor[int32]()
	case reflect.Int64:
		return reflect.TypeFor[int64]()
	case reflect.Uint:
		return reflect.TypeFor[uint]()
	case reflect.Uint8:
		return reflect.TypeFor[uint8]()
	case reflect.Uint16:
		return reflect.TypeFor[uint16]()
	case reflect.Uint32:
		return reflect.TypeFor[uint32]()
	case reflect.Uint64:
		return reflect.TypeFor[uint64]()
	case reflect.Float32:
		return reflect.TypeFor[float32]()
	}
	return reflect.TypeFor[float64]()
}

// widenNumber reads a JSON number as the widest value of the target's
// family: int64 for a signed target, uint64 for an unsigned one, float64 for
// a float. The family conversion then applies its range check.
func widenNumber(n json.Number, out any) (any, error) {
	kind := reflect.TypeOf(out).Elem().Kind()
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return nil, errors.New("the stored number is not an integer that fits an int64")
		}
		return i, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u, err := strconv.ParseUint(string(n), 10, 64)
		if err != nil {
			return nil, errors.New("the stored number is not an integer that fits a uint64")
		}
		return u, nil
	case reflect.Float32, reflect.Float64, reflect.Interface:
		f, err := n.Float64()
		if err != nil {
			// strconv's error quotes the number.
			return nil, errors.New("the stored number does not fit a float64")
		}
		return f, nil
	}
	return n, nil
}

func mismatch(v, want any) error {
	return fmt.Errorf("opened as %T, not %T", v, want)
}

// outOfRange names the target type and not the value, which is plaintext.
func outOfRange(want any) error {
	return fmt.Errorf("the stored value does not fit a %T", want)
}

// setInt writes an integer of any decoded width into a signed target, within
// its range.
func setInt[T ~int | ~int8 | ~int16 | ~int32 | ~int64](v any, out *T, lo, hi int64) error {
	var n int64
	switch i := v.(type) {
	case int32:
		n = int64(i)
	case int64:
		n = i
	case uint32:
		n = int64(i)
	case uint64:
		if i > math.MaxInt64 {
			return outOfRange(*out)
		}
		n = int64(i)
	default:
		return mismatch(v, *out)
	}
	if n < lo || n > hi {
		return outOfRange(*out)
	}
	*out = T(n)
	return nil
}

// setUint writes an integer of any decoded width into an unsigned target,
// within its range.
func setUint[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](v any, out *T, hi uint64) error {
	var n uint64
	switch i := v.(type) {
	case uint32:
		n = uint64(i)
	case uint64:
		n = i
	case int32:
		if i < 0 {
			return outOfRange(*out)
		}
		n = uint64(i)
	case int64:
		if i < 0 {
			return outOfRange(*out)
		}
		n = uint64(i)
	default:
		return mismatch(v, *out)
	}
	if n > hi {
		return outOfRange(*out)
	}
	*out = T(n)
	return nil
}

// setSlice converts each element of an opened array.
func setSlice[E any](v any, out *[]E) error {
	items, ok := v.([]any)
	if !ok {
		return mismatch(v, *out)
	}
	result := make([]E, len(items))
	for i, item := range items {
		if err := convert(item, &result[i]); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}
	}
	*out = result
	return nil
}

// valuesOf reads an opened composite as Values, nested objects included.
func valuesOf(v any) (Values, error) {
	switch obj := v.(type) {
	case vcvalue.Object:
		vals := make(Values, len(obj))
		for _, f := range obj {
			if inner, ok := f.Value.(vcvalue.Object); ok {
				nested, err := valuesOf(inner)
				if err != nil {
					return nil, err
				}
				vals[f.Key] = nested
				continue
			}
			vals[f.Key] = f.Value
		}
		return vals, nil
	case Values:
		return obj, nil
	case map[string]any:
		return Values(obj), nil
	}
	return nil, fmt.Errorf("opened as %T, not an object", v)
}
