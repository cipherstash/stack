package gensupport

import (
	"fmt"
	"math"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// convert writes an opened sealed value into out, a pointer to the Go type
// the struct declares. The engine returns a value at the field's declared
// kind — int32, int64, uint32, uint64, float32, float64, string, []byte,
// bool, or a vcvalue.Object for a composite — and the struct's type is in
// the same family, narrower at most. A value outside the target's range, or
// of another family, is an error.
func convert(v any, out any) error {
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
				return fmt.Errorf("%v does not fit a float32", f)
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
		return fmt.Errorf("the opened value is a %T, which this field's type %T cannot hold", v, out)
	}
	return nil
}

func mismatch(v, want any) error {
	return fmt.Errorf("opened as %T, not %T", v, want)
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
			return fmt.Errorf("%d does not fit a %T", i, *out)
		}
		n = int64(i)
	default:
		return mismatch(v, *out)
	}
	if n < lo || n > hi {
		return fmt.Errorf("%d does not fit a %T", n, *out)
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
			return fmt.Errorf("%d does not fit a %T", i, *out)
		}
		n = uint64(i)
	case int64:
		if i < 0 {
			return fmt.Errorf("%d does not fit a %T", i, *out)
		}
		n = uint64(i)
	default:
		return mismatch(v, *out)
	}
	if n > hi {
		return fmt.Errorf("%d does not fit a %T", n, *out)
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
