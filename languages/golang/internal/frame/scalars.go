package vcffi

import (
	"encoding/binary"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

func (e Encoder) scalar(tag byte, payload []byte) {
	if e.st.err != nil {
		return
	}
	e.push(tag)
	e.push(payload...)
	e.complete()
}

func (e Encoder) Int8(v int8)               { e.scalar(tagInt8, []byte{byte(v)}) }
func (e Encoder) UInt8(v uint8)             { e.scalar(tagUint8, []byte{v}) }
func (e Encoder) Int16(v int16)             { e.scalar(tagInt16, binary.LittleEndian.AppendUint16(nil, uint16(v))) }
func (e Encoder) UInt16(v uint16)           { e.scalar(tagUint16, binary.LittleEndian.AppendUint16(nil, v)) }
func (e Encoder) Int128(v vcvalue.Int128)   { e.scalar(tagInt128, v[:]) }
func (e Encoder) UInt128(v vcvalue.Uint128) { e.scalar(tagUint128, v[:]) }

func (e Encoder) Date(v vcvalue.Date) {
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

// Timestamp keeps the instant and nanoseconds, discarding location and monotonic metadata.
func (e Encoder) Timestamp(v time.Time) {
	e.TimestampParts(vcvalue.Timestamp{Seconds: v.Unix(), Nanoseconds: uint32(v.Nanosecond())})
}
func (e Encoder) TimestampParts(v vcvalue.Timestamp) {
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

// Decimal records a finite decimal. A zero is written without a sign,
// whatever the sign of the value given (ADR 0001).
func (e Encoder) Decimal(v vcvalue.Decimal) {
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

// UUID records sixteen bytes under the Uuid logical type, in the 0xF3
// envelope over a bytes scalar.
func (e Encoder) UUID(u vcvalue.UUID) {
	if e.st.err != nil {
		return
	}
	e.push(uuidEnvelope[:]...)
	e.Bytes(u[:])
}

// uuidEnvelope is the envelope header a UUID starts with, and the header of
// a UUID's typed null: the Uuid logical type, no parameter, over bytes.
var uuidEnvelope = [3]byte{tagEnvelope, logicalUUID, 0}

// Tagged records a physical scalar under a logical id this build does not
// know, in the 0xF3 envelope: what Unmarshal produced for such a value, so
// it goes back out unchanged. An id this build knows, or a value that is
// not a physical scalar, is refused.
func (e Encoder) Tagged(t vcvalue.Tagged) {
	if e.st.err != nil {
		return
	}
	if t.ID <= logicalLastKnown {
		e.st.fail(vcvalue.ErrInvalidTagged)
		return
	}
	e.push(tagEnvelope, t.ID, t.Param)
	if !e.physical(t.V) {
		e.st.fail(vcvalue.ErrInvalidTagged)
	}
}

// physical writes v through its scalar channel, for the kinds the envelope
// may carry, and reports whether v was one of them.
func (e Encoder) physical(v any) bool {
	switch x := v.(type) {
	case nil:
		e.Null()
	case bool:
		e.Bool(x)
	case int8:
		e.Int8(x)
	case uint8:
		e.UInt8(x)
	case int16:
		e.Int16(x)
	case uint16:
		e.UInt16(x)
	case int32:
		e.Int32(x)
	case uint32:
		e.UInt32(x)
	case int64:
		e.Int64(x)
	case uint64:
		e.UInt64(x)
	case int:
		// As Encode writes int and uint everywhere else.
		e.Int64(int64(x))
	case uint:
		e.UInt64(uint64(x))
	case vcvalue.Int128:
		e.Int128(x)
	case vcvalue.Uint128:
		e.UInt128(x)
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
		return vcvalue.Int128(b), nil
	case tagUint128:
		return vcvalue.Uint128(b), nil
	case tagDate:
		d, err := vcvalue.DateFromDaysCE(int32(binary.LittleEndian.Uint32(b)))
		if err != nil {
			return nil, ErrMalformed
		}
		return d, nil
	case tagTimestamp:
		// A leap second (nanoseconds of one billion or more) has no count
		// since the epoch and is refused by Validate (ADR 0001).
		t := vcvalue.Timestamp{Seconds: int64(binary.LittleEndian.Uint64(b)), Nanoseconds: binary.LittleEndian.Uint32(b[8:])}
		if t.Validate() != nil {
			return nil, ErrMalformed
		}
		return time.Unix(t.Seconds, int64(t.Nanoseconds)).UTC(), nil
	case tagDecimal:
		flags := binary.LittleEndian.Uint32(b)
		if flags&0x7f00ffff != 0 {
			return nil, ErrMalformed
		}
		d := vcvalue.Decimal{Scale: uint8(flags >> 16), Negative: flags>>31 != 0}
		copy(d.Coefficient[:], b[4:])
		if d.Validate() != nil {
			return nil, ErrMalformed
		}
		// A negative zero reads as zero, with its scale kept (ADR 0001).
		return d.Normalized(), nil
	default:
		return nil, ErrMalformed
	}
}

// fixedWidth is the payload width of a fixed-width scalar tag, or zero for
// a tag whose payload is not fixed (or that has none).
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

// numericTag reports whether tag is a plain int or float: what a typed null
// in the envelope may ride on under a timestamp unit or an unknown id.
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

// fixedTags is the tag each FixedType is written with, all but the UUID,
// whose header is uuidEnvelope over tagBytes.
var fixedTags = map[vcvalue.FixedType]byte{
	vcvalue.TypeInt8:      tagInt8,
	vcvalue.TypeInt16:     tagInt16,
	vcvalue.TypeInt32:     tagInt32,
	vcvalue.TypeInt64:     tagInt64,
	vcvalue.TypeInt128:    tagInt128,
	vcvalue.TypeUint8:     tagUint8,
	vcvalue.TypeUint16:    tagUint16,
	vcvalue.TypeUint32:    tagUint32,
	vcvalue.TypeUint64:    tagUint64,
	vcvalue.TypeUint128:   tagUint128,
	vcvalue.TypeFloat32:   tagFloat32,
	vcvalue.TypeFloat64:   tagFloat64,
	vcvalue.TypeDate:      tagDate,
	vcvalue.TypeTimestamp: tagTimestamp,
	vcvalue.TypeDecimal:   tagDecimal,
}

// TypedNull records an absent value of a fixed-width type: a null padded to
// the length of a value of t, so the two seal to the same length. Encode
// writes one for a nil pointer to a fixed-width type; this channel is for a
// caller that knows the type some other way. An invalid t fails the
// encode.
func (e Encoder) TypedNull(t vcvalue.FixedType) {
	if e.st.err != nil {
		return
	}
	if !t.Valid() {
		e.st.fail(vcvalue.ErrInvalidFixedType)
		return
	}
	var header []byte
	var payload int
	if t == vcvalue.TypeUUID {
		header, payload = append(uuidEnvelope[:], tagBytes), len(vcvalue.UUID{})
	} else {
		tag := fixedTags[t]
		header, payload = []byte{tag}, fixedWidth(tag)
	}
	e.push(tagTypedNull)
	e.push(header...)
	// One byte of the value's length went to tagTypedNull.
	e.push(make([]byte, payload-1)...)
	e.complete()
}

// decodeTypedNull reads a typed null after its tag, as strictly as the Rust
// codec does, so every absence has one encoding: a header a value of some
// fixed-width type starts with, then exactly the zero padding to that
// value's length. It decodes as nil. A frame is never sealed, so the padding
// means nothing once the value is out, and Rust's frame writer writes the
// plain null for it too.
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
			// The nanosecond unit has the shorthand Timestamp tag.
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
			// A logical id this build does not know, over an int or float.
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
