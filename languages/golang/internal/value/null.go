package vcvalue

// FixedType names a fixed-width type: one whose every value seals to a leaf
// of the same length. An absent value of such a type is written as a typed
// null, padded to that length, so a sealed absence cannot be told from a
// sealed value by its length, as a plain null (one byte) could be.
//
// bool is fixed width too, but its leaf is already as short as a null's,
// and text and bytes are variable width, so neither has a FixedType. A UUID's
// sixteen bytes are fixed by its type, so it has one.
type FixedType uint8

// The fixed-width types, each named for the Go type it is written from.
// TypeInt64 and TypeUint64 cover int and uint too, as the codec writes them.
const (
	TypeInt8 FixedType = iota + 1
	TypeInt16
	TypeInt32
	TypeInt64
	TypeInt128
	TypeUint8
	TypeUint16
	TypeUint32
	TypeUint64
	TypeUint128
	TypeFloat32
	TypeFloat64
	TypeDate
	TypeTimestamp
	TypeDecimal
	TypeUUID
)

// Valid reports whether t is one of the named fixed-width types.
func (t FixedType) Valid() bool {
	return t >= TypeInt8 && t <= TypeUUID
}

// TypedNull is an absent value of a fixed-width type, for a caller whose Go
// type cannot say what is missing: a nil in a map[string]any or an []any.
// A nil pointer to a fixed-width type (*int32, *time.Time, *Date, …) is
// written as a typed null without it.
//
// It only encodes. A typed null decodes as nil, like every null: once
// decrypted, an absent value is absent whatever its type.
type TypedNull struct {
	Type FixedType
}
