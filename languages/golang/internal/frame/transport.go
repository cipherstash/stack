package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// The tags of the value encoding. A tag is the first byte of an encoded
// node. The tag says what kind of node follows.
//
// Each scalar tag has the same value as the tag of a sealed leaf in
// vitaminc-aead, so one byte means one type in both encodings. The
// sealed-leaf tags never change. The tags for an array and an object exist
// only in the transport bytes. The sealed format has no tags for containers,
// because the ciphertext tree has a node for each container.
//
// The transport bytes are not a storage format. See the package
// documentation.
const (
	tagNull      = 0x00
	tagUndefined = 0x01
	tagFalse     = 0x02
	tagTrue      = 0x03
	tagInt32     = 0x04
	tagInt64     = 0x05
	tagUint32    = 0x06
	tagUint64    = 0x07
	tagFloat32   = 0x08
	tagFloat64   = 0x09
	tagString    = 0x0A
	tagBytes     = 0x0B
	tagInt8      = 0x0C
	tagUint8     = 0x0D
	tagInt16     = 0x0E
	tagUint16    = 0x0F
	tagInt128    = 0x10
	tagUint128   = 0x11
	tagDate      = 0x12
	tagTimestamp = 0x13
	tagDecimal   = 0x14
	// tagTypedNull starts a typed null. A typed null is an absent value of a
	// fixed-width type. The bytes are tagTypedNull, then the header that a
	// value of the type starts with, then zeros. A typed null is as long as
	// an encoded value of the type.
	tagTypedNull = 0x15
	tagArray     = 0xF0
	tagObject    = 0xF1
	// tagPassthrough starts a passthrough value: the tag, then one value
	// node. A passthrough value is neither encrypted nor authenticated. This
	// tag exists only in the transport bytes, as the array and object tags
	// do.
	tagPassthrough = 0xF2
	// tagEnvelope starts an envelope. An envelope records a logical type
	// that has no tag of its own. The bytes are the tag, the id of the
	// logical type, a parameter, then a physical scalar. A physical scalar
	// is a scalar that the encoding stores as it is, such as an integer or
	// bytes. The tag 0xF4 is reserved for a longer envelope, and the
	// decoders refuse it.
	tagEnvelope = 0xF3
)

// The ids of the logical types, as an envelope records them. Undefined,
// Date, Decimal, and a Timestamp in nanoseconds each have a tag of their
// own. An envelope is never used for those four, so every value has exactly
// one encoding.
const (
	logicalUndefined = 1
	logicalDate      = 2
	logicalTimestamp = 3
	logicalDecimal   = 4
	logicalUUID      = 5
	// logicalLastKnown is the highest id that this version of the codec
	// knows. A value with a higher id decodes as a [Tagged]. A Tagged
	// encodes as the same bytes.
	logicalLastKnown = logicalUUID
)

// The units of a timestamp, as the parameter of an envelope records them. A
// timestamp in nanoseconds uses tagTimestamp. Only a timestamp in seconds,
// milliseconds, or microseconds uses an envelope.
const (
	unitSeconds = 0
	unitMillis  = 1
	unitMicros  = 2
	unitNanos   = 3
)

// maxUint32 is the largest length or count that the codec writes or reads.
// Every length and count is an unsigned 32-bit integer in little-endian byte
// order.
//
// The constant has the type uint64. An untyped 1<<32-1 does not compile when
// it is compared with an int on a 32-bit GOARCH, because the constant
// overflows int.
//
// The check is needed on those platforms. There, a count that is too large
// converts to a negative int. A negative count would pass the check against
// the bytes remaining. The call to make would then panic. The decoder must
// return ErrMalformed instead.
//
// Each comparison converts its int operand to uint64. That conversion loses
// nothing for a value that is not negative. The n < 0 checks refuse a
// negative value first.
const maxUint32 = uint64(1<<32 - 1)

// maxDepth is the deepest nesting that the codec accepts. The Rust codec has
// the same limit. The limit stops hostile input from overflowing the stack.
const maxDepth = 128

// maxEagerCapacity is the largest capacity that a decoder reserves before it
// reads the items of a container. The Rust codecs have the same limit,
// MAX_EAGER_CAPACITY.
//
// The reader already checks one count against the bytes remaining. That
// check does not limit the total that nested containers reserve. One level
// of nesting takes 5 to 9 encoded bytes, but a reserved item takes many
// times that. Up to maxDepth containers can each have a reservation at the
// same time. Without this limit, about 1 MB of hostile bytes could reserve
// gigabytes of memory.
//
// A slice still grows past the limit as items are appended. Only the first
// reservation is limited.
const maxEagerCapacity = 1024

func eagerCap(n int) int {
	// On a 64-bit platform n is never negative, because a 32-bit count fits
	// an int. On a 32-bit GOARCH, a hostile count of 2^31 or more converts
	// to a negative int. Without this check, min would pass the negative
	// value to make.
	if n < 0 {
		return 0
	}
	return min(n, maxEagerCapacity)
}

// ErrMalformed is the error the decoders return for transport bytes or a
// storage blob that they cannot parse. Examples are truncated input, input
// that is nested too deep, a hostile count, a duplicate key, and an unknown
// tag. The error does not say which. The decoders treat their input as
// hostile, so they report no detail about it.
//
// The decoders return ErrMalformed itself, never wrapped. errors.Is and ==
// therefore give the same answer today. Use errors.Is.
//
// A [LeafSet] that is set up wrongly is a different failure. The caller made
// that mistake, so the bytes are not at fault. [UnmarshalCipherText] reports
// it with a different error that names the mistake.
var ErrMalformed = errors.New("frame: malformed transport bytes or storage blob")

// ErrTooDeep is the error the encoders return for a value or a ciphertext
// tree that is nested deeper than maxDepth. The caller's own code built that
// value, so the caller can match on this error. The decoders return
// [ErrMalformed] for input that is nested too deep, as they do for all bad
// input.
var ErrTooDeep = errors.New("frame: value is nested too deeply")

func appendLen(out []byte, n int) ([]byte, error) {
	if n < 0 || uint64(n) > maxUint32 {
		return nil, fmt.Errorf("frame: length %d out of range", n)
	}
	return binary.LittleEndian.AppendUint32(out, uint32(n)), nil
}

func appendChunk(out, chunk []byte) ([]byte, error) {
	out, err := appendLen(out, len(chunk))
	if err != nil {
		return nil, err
	}
	return append(out, chunk...), nil
}

// reader reads a buffer from start to end, and records how many bytes it has
// read. A decoder uses that number to check that it read the whole buffer.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) byteTag() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, ErrMalformed
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.buf)-r.pos {
		return nil, ErrMalformed
	}
	s := r.buf[r.pos : r.pos+n]
	r.pos += n
	return s, nil
}

func (r *reader) u32() (int, error) {
	s, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return int(binary.LittleEndian.Uint32(s)), nil
}

// count reads a 32-bit item count. The function refuses a count that is
// greater than the number of bytes remaining, because every item takes at
// least one byte. Hostile input therefore cannot make a decoder reserve much
// memory.
//
// The function also refuses a negative n, as take and appendLen do. On a
// 32-bit GOARCH, a count of 2^31 or more converts to a negative int. A
// negative count would pass the check against the bytes remaining. The call
// to make would then panic.
func (r *reader) count() (int, error) {
	n, err := r.u32()
	if err != nil {
		return 0, err
	}
	if n < 0 || n > len(r.buf)-r.pos {
		return 0, ErrMalformed
	}
	return n, nil
}

func (r *reader) finished() bool {
	return r.pos == len(r.buf)
}

// str reads a string: a length, then that many bytes. The bytes must be
// valid UTF-8.
func (r *reader) str() (string, error) {
	n, err := r.count()
	if err != nil {
		return "", err
	}
	s, err := r.take(n)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(s) {
		return "", ErrMalformed
	}
	return string(s), nil
}
