package frame

import (
	"encoding/binary"
	"math"
	"math/big"
	"time"
)

// Unmarshal decodes the transport bytes of a value into Go values:
//
//   - Null and Undefined decode as nil. Go has no undefined value.
//   - A typed null decodes as nil. The type of an absent value matters only
//     while the value is sealed. The nil therefore encodes again as the
//     plain null.
//   - Bool decodes as bool.
//   - Int32 decodes as int32.
//   - Int64 decodes as int64.
//   - Uint32 decodes as uint32.
//   - Uint64 decodes as uint64.
//   - Float32 decodes as float32.
//   - Float64 decodes as float64.
//   - String decodes as string.
//   - Bytes decodes as []byte.
//   - Array decodes as []any.
//   - Object decodes as [Object], an ordered []Field.
//   - Passthrough decodes as Plain{V: v}, where v is the decoded value.
//     Plain marks a value that was not encrypted.
//   - An envelope starts with the tag 0xF3, and decodes by its logical type.
//     A timestamp in seconds, milliseconds, or microseconds decodes as
//     time.Time. A UUID decodes as UUID. A logical type id that this version
//     does not know decodes as [Tagged]. A Tagged encodes as the same bytes.
//   - The 8-bit, 16-bit, and 128-bit integers decode as int8, uint8, int16,
//     uint16, Int128, and Uint128.
//   - Date decodes as Date, Timestamp as time.Time, and Decimal as Decimal.
//
// A value type that is published decodes as the type it is published as. For
// example, Date decodes as encrypt.Date in a program that links package
// encrypt. See [Publish].
//
// Go has a type for every tag, so Unmarshal never widens a value. The 32-bit
// tags decode as int32, uint32, and float32, never as 64-bit types.
// JavaScript differs: it decodes every integer tag as a BigInt, and widens
// Float32 to a number.
func Unmarshal(buf []byte) (any, error) {
	r := &reader{buf: buf}
	v, err := decodeValue(r, 0)
	if err != nil {
		return nil, err
	}
	if !r.finished() {
		return nil, ErrMalformed
	}
	return v, nil
}

func decodeValue(r *reader, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	return decodeTagged(r, tag, depth)
}

// decodeTagged decodes a node. The caller has already read the tag of the
// node.
func decodeTagged(r *reader, tag byte, depth int) (any, error) {
	switch tag {
	case tagInt8, tagUint8, tagInt16, tagUint16, tagInt128, tagUint128, tagDate, tagTimestamp, tagDecimal:
		return decodeScalar(r, tag)
	case tagNull, tagUndefined:
		return nil, nil
	case tagFalse:
		return false, nil
	case tagTrue:
		return true, nil
	case tagInt32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return int32(binary.LittleEndian.Uint32(s)), nil
	case tagInt64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.LittleEndian.Uint64(s)), nil
	case tagUint32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint32(s), nil
	case tagUint64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint64(s), nil
	case tagFloat32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(s)), nil
	case tagFloat64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(s)), nil
	case tagString:
		return r.str()
	case tagBytes:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		s, err := r.take(n)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(s))
		copy(out, s)
		return out, nil
	case tagArray:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, eagerCap(n))
		for range n {
			item, err := decodeValue(r, depth+1)
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
		// A duplicate key is refused. The ciphertext decoder and both Rust
		// decoders refuse one too. If an Object with a duplicate key were
		// encoded again through a Go map, one entry would be lost with no
		// error.
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
			value, err := decodeValue(r, depth+1)
			if err != nil {
				return nil, err
			}
			fields = append(fields, Field{Key: key, Value: value})
		}
		return fields, nil
	case tagPassthrough:
		// A passthrough value decodes as Plain{V: v}, where v is the decoded
		// value. Plain is also how a caller asks the Encoder for
		// passthrough. The caller can therefore tell that the value was not
		// encrypted.
		inner, err := decodeValue(r, depth+1)
		if err != nil {
			return nil, err
		}
		return Plain{V: inner}, nil
	case tagEnvelope:
		return decodeEnvelope(r)
	case tagTypedNull:
		return decodeTypedNull(r)
	default:
		return nil, ErrMalformed
	}
}

// physicalTag reports whether tag is the tag of a physical scalar. Only a
// physical scalar can follow the header of an envelope. The tags of the
// logical types Undefined, Date, Timestamp, and Decimal are not physical.
// The container tags are not physical either.
func physicalTag(tag byte) bool {
	switch tag {
	case tagNull, tagFalse, tagTrue, tagInt32, tagInt64, tagUint32, tagUint64, tagFloat32, tagFloat64,
		tagString, tagBytes, tagInt8, tagUint8, tagInt16, tagUint16, tagInt128, tagUint128:
		return true
	}
	return false
}

// decodeEnvelope reads an envelope, after its tag 0xF3. An envelope is the
// id of a logical type, a parameter, and a physical scalar. Every value has
// exactly one encoding, so three kinds of envelope are malformed:
//
//   - one for a logical type that has a tag of its own
//   - one with an id of zero
//   - one with a known id and a parameter that the type does not accept
func decodeEnvelope(r *reader) (any, error) {
	id, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	param, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	if !physicalTag(tag) {
		return nil, ErrMalformed
	}
	physical, err := decodeTagged(r, tag, maxDepth)
	if err != nil {
		return nil, err
	}
	switch id {
	case 0, logicalUndefined, logicalDate, logicalDecimal:
		return nil, ErrMalformed
	case logicalTimestamp:
		return envelopeTimestamp(param, physical)
	case logicalUUID:
		b, ok := physical.([]byte)
		if param != 0 || !ok || len(b) != 16 {
			return nil, ErrMalformed
		}
		var u UUID
		copy(u[:], b)
		return public(u), nil
	default:
		return Tagged{ID: id, Param: param, V: physical}, nil
	}
}

// envelopeTimestamp converts a count of seconds, milliseconds, or
// microseconds since the epoch to a time.Time. The instant must be in the
// range that the encoding accepts, about the years -9999 to 9999. See
// [Timestamp]. The function refuses the nanosecond unit, because a timestamp
// in nanoseconds uses tagTimestamp.
func envelopeTimestamp(unit byte, physical any) (any, error) {
	var per int64
	switch unit {
	case unitSeconds:
		per = 1_000_000_000
	case unitMillis:
		per = 1_000_000
	case unitMicros:
		per = 1_000
	default:
		return nil, ErrMalformed
	}
	var t Timestamp
	if count, ok := smallIntegerOf(physical); ok {
		// Most counts fit an int64, including every Date that Node writes.
		// Those counts are converted without math/big. The count is split
		// into whole seconds and a remainder. The remainder is never
		// negative, as with DivMod below.
		perSecond := 1_000_000_000 / per
		seconds, rem := count/perSecond, count%perSecond
		if rem < 0 {
			seconds, rem = seconds-1, rem+perSecond
		}
		t = Timestamp{Seconds: seconds, Nanoseconds: uint32(rem * per)}
	} else {
		count, ok := wideIntegerOf(physical)
		if !ok {
			return nil, ErrMalformed
		}
		nanos := new(big.Int).Mul(count, big.NewInt(per))
		seconds, sub := new(big.Int).DivMod(nanos, big.NewInt(1_000_000_000), new(big.Int))
		if !seconds.IsInt64() {
			return nil, ErrMalformed
		}
		t = Timestamp{Seconds: seconds.Int64(), Nanoseconds: uint32(sub.Int64())}
	}
	if t.Validate() != nil {
		return nil, ErrMalformed
	}
	return time.Unix(t.Seconds, int64(t.Nanoseconds)).UTC(), nil
}

// smallIntegerOf returns the value of a decoded integer that fits an int64.
// The second result is false for any other value.
func smallIntegerOf(v any) (int64, bool) {
	switch x := v.(type) {
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), x <= math.MaxInt64
	}
	return 0, false
}

// wideIntegerOf returns the value of a decoded integer that smallIntegerOf
// does not accept: a uint64 above math.MaxInt64, an Int128, or a Uint128.
func wideIntegerOf(v any) (*big.Int, bool) {
	switch x := internal(v).(type) {
	case uint64:
		return new(big.Int).SetUint64(x), true
	case Int128:
		value, ok := new(big.Int).SetString(x.String(), 10)
		return value, ok
	case Uint128:
		value, ok := new(big.Int).SetString(x.String(), 10)
		return value, ok
	}
	return nil, false
}
