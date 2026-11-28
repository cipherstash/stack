package frame

import (
	"encoding/binary"
	"time"
)

func (e Encoder) scalar(tag byte, payload []byte) {
	if e.st.err != nil {
		return
	}
	e.push(tag)
	e.push(payload...)
	e.complete()
}

func (e Encoder) Int8(v int8)       { e.scalar(tagInt8, []byte{byte(v)}) }
func (e Encoder) Uint8(v uint8)     { e.scalar(tagUint8, []byte{v}) }
func (e Encoder) Int16(v int16)     { e.scalar(tagInt16, binary.LittleEndian.AppendUint16(nil, uint16(v))) }
func (e Encoder) Uint16(v uint16)   { e.scalar(tagUint16, binary.LittleEndian.AppendUint16(nil, v)) }
func (e Encoder) Int128(v Int128)   { e.scalar(tagInt128, v[:]) }
func (e Encoder) Uint128(v Uint128) { e.scalar(tagUint128, v[:]) }

func (e Encoder) Date(v Date) {
	if e.st.err != nil {
		return
	}
	days, err := v.DaysFromCE()
	if err != nil {
		e.st.fail(err)
		return
	}
	e.scalar(tagDate, binary.LittleEndian.AppendUint32(nil, uint32(days)))
}

// Timestamp records the instant of v, to the nanosecond. Timestamp does not
// record the location of v or its monotonic clock reading.
func (e Encoder) Timestamp(v time.Time) {
	e.TimestampParts(Timestamp{Seconds: v.Unix(), Nanoseconds: uint32(v.Nanosecond())})
}
func (e Encoder) TimestampParts(v Timestamp) {
	if e.st.err != nil {
		return
	}
	if err := v.Validate(); err != nil {
		e.st.fail(err)
		return
	}
	b := binary.LittleEndian.AppendUint64(nil, uint64(v.Seconds))
	b = binary.LittleEndian.AppendUint32(b, v.Nanoseconds)
	e.scalar(tagTimestamp, b)
}

// Decimal records a finite decimal. Decimal writes a zero with no sign,
// whatever the sign of v.
func (e Encoder) Decimal(v Decimal) {
	if e.st.err != nil {
		return
	}
	if err := v.Validate(); err != nil {
		e.st.fail(err)
		return
	}
	v = v.Normalized()
	flags := uint32(v.Scale) << 16
	if v.Negative {
		flags |= 0x80000000
	}
	b := binary.LittleEndian.AppendUint32(nil, flags)
	b = append(b, v.Coefficient[:]...)
	e.scalar(tagDecimal, b)
}

// UUID records the sixteen bytes of u with the logical type Uuid. The bytes
// are an envelope around a bytes scalar. The envelope starts with the tag
// 0xF3.
func (e Encoder) UUID(u UUID) {
	if e.st.err != nil {
		return
	}
	e.push(uuidEnvelope[:]...)
	e.Bytes(u[:])
}

// uuidEnvelope is the envelope header that starts an encoded UUID. The typed
// null of a UUID uses the same header. The header is the envelope tag, the
// id of the logical type Uuid, and a parameter of zero.
var uuidEnvelope = [3]byte{tagEnvelope, logicalUUID, 0}

// Tagged records a physical scalar with a logical type id that this version
// of the codec does not know. The bytes are an envelope, as for any logical
// type with no tag of its own. [Unmarshal] returns a Tagged for such a
// value, and Tagged writes the same bytes back.
//
// Tagged refuses an id that this version knows. Tagged also refuses a V that
// is not a physical scalar.
func (e Encoder) Tagged(t Tagged) {
	if e.st.err != nil {
		return
	}
	if t.ID <= logicalLastKnown {
		e.st.fail(ErrInvalidTagged)
		return
	}
	e.push(tagEnvelope, t.ID, t.Param)
	if !e.physical(t.V) {
		e.st.fail(ErrInvalidTagged)
	}
}

// physical writes v with the scalar method for its type, when an envelope
// can contain that kind of scalar. The function reports whether it wrote v.
func (e Encoder) physical(v any) bool {
	switch x := internal(v).(type) {
	case nil:
		e.Null()
	case bool:
		e.Bool(x)
	case int8:
		e.Int8(x)
	case uint8:
		e.Uint8(x)
	case int16:
		e.Int16(x)
	case uint16:
		e.Uint16(x)
	case int32:
		e.Int32(x)
	case uint32:
		e.Uint32(x)
	case int64:
		e.Int64(x)
	case uint64:
		e.Uint64(x)
	case int:
		// Encode writes an int and a uint the same way.
		e.Int64(int64(x))
	case uint:
		e.Uint64(uint64(x))
	case Int128:
		e.Int128(x)
	case Uint128:
		e.Uint128(x)
	case float32:
		e.Float32(x)
	case float64:
		e.Float64(x)
	case string:
		e.String(x)
	case []byte:
		e.Bytes(x)
	default:
		return false
	}
	return true
}

func decodeScalar(r *reader, tag byte) (any, error) {
	b, err := r.take(fixedWidth(tag))
	if err != nil {
		return nil, err
	}
	switch tag {
	case tagInt8:
		return int8(b[0]), nil
	case tagUint8:
		return b[0], nil
	case tagInt16:
		return int16(binary.LittleEndian.Uint16(b)), nil
	case tagUint16:
		return binary.LittleEndian.Uint16(b), nil
	case tagInt128:
		return public(Int128(b)), nil
	case tagUint128:
		return public(Uint128(b)), nil
	case tagDate:
		d, err := DateFromDaysCE(int32(binary.LittleEndian.Uint32(b)))
		if err != nil {
			return nil, ErrMalformed
		}
		return public(d), nil
	case tagTimestamp:
		// Validate refuses nanoseconds of one billion or more. Such a value
		// is a leap second. A leap second has no count since the epoch.
		t := Timestamp{Seconds: int64(binary.LittleEndian.Uint64(b)), Nanoseconds: binary.LittleEndian.Uint32(b[8:])}
		if t.Validate() != nil {
			return nil, ErrMalformed
		}
		return time.Unix(t.Seconds, int64(t.Nanoseconds)).UTC(), nil
	case tagDecimal:
		flags := binary.LittleEndian.Uint32(b)
		if flags&0x7f00ffff != 0 {
			return nil, ErrMalformed
		}
		d := Decimal{Scale: uint8(flags >> 16), Negative: flags>>31 != 0}
		copy(d.Coefficient[:], b[4:])
		if d.Validate() != nil {
			return nil, ErrMalformed
		}
		// A negative zero reads as zero, with its scale kept.
		return public(d.Normalized()), nil
	default:
		return nil, ErrMalformed
	}
}

// fixedWidth returns the number of payload bytes that follow a fixed-width
// scalar tag. The result is zero for a tag whose payload varies in length,
// and for a tag with no payload.
func fixedWidth(tag byte) int {
	switch tag {
	case tagInt8, tagUint8:
		return 1
	case tagInt16, tagUint16:
		return 2
	case tagInt32, tagUint32, tagFloat32, tagDate:
		return 4
	case tagInt64, tagUint64, tagFloat64:
		return 8
	case tagTimestamp:
		return 12
	case tagInt128, tagUint128, tagDecimal:
		return 16
	}
	return 0
}

// numericTag reports whether tag is an integer tag, or a float tag when
// floats is true. A typed null in an envelope must name such a tag as its
// scalar. Under a timestamp unit the scalar must be an integer. Under an id
// that this version does not know, the scalar can be an integer or a float.
func numericTag(tag byte, floats bool) bool {
	switch tag {
	case tagInt8, tagUint8, tagInt16, tagUint16, tagInt32, tagUint32, tagInt64, tagUint64,
		tagInt128, tagUint128:
		return true
	case tagFloat32, tagFloat64:
		return floats
	}
	return false
}

// nullOf returns the typed null of a type whose values are written with the
// scalar tag. The bytes are tagTypedNull, then tag, then zeros. The typed
// null is as long as an encoded value of the type, so both seal to the same
// length. The first byte, tagTypedNull, counts towards that length. The
// zeros are therefore one byte shorter than the payload.
func nullOf(tag byte) []byte {
	return typedNull([]byte{tag}, fixedWidth(tag))
}

// uuidNull is the typed null of a UUID. The header is the UUID envelope,
// then the bytes tag. The sealed leaf of a UUID has no length prefix. The
// padding is therefore sized for the sixteen bytes of the UUID alone.
var uuidNull = typedNull(append(uuidEnvelope[:], tagBytes), len(UUID{}))

func typedNull(header []byte, payload int) []byte {
	out := append([]byte{tagTypedNull}, header...)
	return append(out, make([]byte, payload-1)...)
}

// typedNull records an absent value of a fixed-width type. null is the bytes
// that nullOf or uuidNull built. Encode calls typedNull for a nil pointer to
// a fixed-width type.
func (e Encoder) typedNull(null []byte) {
	if e.st.err != nil {
		return
	}
	e.push(null...)
	e.complete()
}

// decodeTypedNull reads a typed null, after its tag. A typed null has two
// parts:
//
//   - the header that starts a value of some fixed-width type
//   - exactly the zeros that pad the typed null to the length of that value
//
// The function refuses anything else, as the Rust codec does. Every absent
// value therefore has one encoding.
//
// A typed null decodes as nil. The padding matters only when a value is
// sealed. A frame is never sealed. The frame writer in Rust therefore writes
// the plain null for an absent value too.
func decodeTypedNull(r *reader) (any, error) {
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	var payload int
	switch {
	case tag == tagEnvelope:
		h, err := r.take(3)
		if err != nil {
			return nil, err
		}
		id, param, physical := h[0], h[1], h[2]
		switch id {
		case logicalTimestamp:
			// A timestamp in nanoseconds uses tagTimestamp, so an envelope
			// must not name that unit.
			if param > unitMicros || !numericTag(physical, false) {
				return nil, ErrMalformed
			}
			payload = fixedWidth(physical)
		case logicalUUID:
			if param != 0 || physical != tagBytes {
				return nil, ErrMalformed
			}
			payload = 16
		case 0, logicalUndefined, logicalDate, logicalDecimal:
			return nil, ErrMalformed
		default:
			// An id that this version does not know. The scalar must be an
			// integer or a float.
			if !numericTag(physical, true) {
				return nil, ErrMalformed
			}
			payload = fixedWidth(physical)
		}
	case tag == tagDate || tag == tagTimestamp || tag == tagDecimal || numericTag(tag, true):
		payload = fixedWidth(tag)
	default:
		return nil, ErrMalformed
	}
	padding, err := r.take(payload - 1)
	if err != nil {
		return nil, err
	}
	for _, b := range padding {
		if b != 0 {
			return nil, ErrMalformed
		}
	}
	return nil, nil
}
