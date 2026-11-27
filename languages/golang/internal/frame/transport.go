package vcffi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Transport framing tags. The scalar tags mirror vitaminc-aead's frozen
// sealed-leaf tag table so the two tables can't drift apart on
// meaning; the ARRAY/OBJECT container tags are transport-local (the sealed
// format has no container tags — container shape rides on the ciphertext
// tree). See the package doc: this transport encoding is NOT a storage
// format.
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
	// tagTypedNull is an absent value of a fixed-width type, padded to that
	// type's leaf length: the tag, the header a value of the type starts
	// with, then zeros (vitaminc#493).
	tagTypedNull = 0x15
	tagArray     = 0xF0
	tagObject    = 0xF1
	// tagPassthrough wraps one value node that travels in the clear
	// (unencrypted, unauthenticated). Transport-local, like array/object.
	tagPassthrough = 0xF2
	// tagEnvelope carries a logical type with no shorthand tag over a
	// physical scalar: id, parameter, then the scalar (ADR 0001). 0xF4 is
	// reserved for a longer envelope and is refused.
	tagEnvelope = 0xF3
)

// Logical type ids, as the envelope spells them. Undefined, Date, Decimal
// and nanosecond Timestamp have shorthand tags of their own, so the
// envelope never carries them: there is one encoding per value.
const (
	logicalUndefined = 1
	logicalDate      = 2
	logicalTimestamp = 3
	logicalDecimal   = 4
	logicalUUID      = 5
	// logicalLastKnown is the highest id this build knows. Any id above it
	// is read and re-encoded unchanged as a vcvalue.Tagged.
	logicalLastKnown = logicalUUID
)

// Timestamp units, as the envelope's parameter spells them. Nanoseconds is
// the shorthand Timestamp tag, so only the coarser units use the envelope.
const (
	unitSeconds = 0
	unitMillis  = 1
	unitMicros  = 2
	unitNanos   = 3
)

// maxUint32 bounds every length/count written or read (all are u32 LE).
// Typed uint64, not an untyped constant: an untyped 1<<32-1 compared against
// an int fails to compile on 32-bit GOARCH (constant overflows int), and the
// guard is load-bearing there — an oversized count coerced to a negative int
// would slip past the remaining-bytes check and panic in make instead of
// returning ErrMalformed. Comparisons convert the int operand to uint64
// (always lossless for non-negative values, which the n < 0 guards ensure).
const maxUint32 = uint64(1<<32 - 1)

// maxDepth mirrors the Rust transport codec's recursion bound, keeping a
// hostile nesting depth from overflowing the stack.
const maxDepth = 128

// maxEagerCapacity clamps the up-front reservation of a count-driven
// allocation. The reader's count guard bounds a single reservation against
// the bytes remaining, but not the sum of live reservations: a container
// nesting level costs 5-9 wire bytes while a reserved slot costs many times
// that, and up to maxDepth ancestor reservations are live at once — so ~1 MB
// of hostile bytes could otherwise pin gigabytes. Mirrors the Rust codecs'
// MAX_EAGER_CAPACITY. Slices still grow past the clamp on append; only the
// initial reservation is bounded.
const maxEagerCapacity = 1024

func eagerCap(n int) int {
	// n < 0 is unreachable on 64-bit (u32 counts are non-negative in a 64-bit
	// int) but load-bearing on 32-bit GOARCH, where a hostile prefix >= 2^31
	// coerces negative and min() would pass it through to make().
	if n < 0 {
		return 0
	}
	return min(n, maxEagerCapacity)
}

// ErrMalformed is returned by the decoders for any transport buffer or
// storage blob that does not parse: truncated, over-deep, hostile counts,
// duplicate keys, unknown tags. Deliberately unspecific — the decoders treat their input as
// hostile and do not distinguish *how* it is malformed. It is returned bare,
// never wrapped, so errors.Is and == are equivalent today; prefer errors.Is.
//
// A misconfigured [LeafSet] is a different class of failure — the binding's
// own wiring, not hostile bytes — and [UnmarshalCipherText] reports it with a
// distinct, attributable error rather than folding it into ErrMalformed.
var ErrMalformed = errors.New("vcffi: malformed transport bytes or storage blob")

// ErrTooDeep is returned by the encoders when a value or ciphertext tree
// exceeds the recursion bound (the decoders fold over-deep input into
// [ErrMalformed] — hostile bytes stay unspecific by design, but a too-deep
// value handed in by the caller's own code is worth matching on).
var ErrTooDeep = errors.New("vcffi: value is nested too deeply")

func appendLen(out []byte, n int) ([]byte, error) {
	if n < 0 || uint64(n) > maxUint32 {
		return nil, fmt.Errorf("vcffi: length %d out of range", n)
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

// reader is a cursor over a transport buffer, tracking bytes consumed so a
// decode can insist the whole buffer was used.
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

// count reads a u32 item count, rejecting counts that exceed the bytes
// remaining (every item costs at least one byte) so hostile input cannot
// drive a huge preallocation. The n < 0 guard matches take/appendLen: on
// 32-bit GOARCH a prefix >= 2^31 coerces to a negative int, which would slip
// past the remaining-bytes check and panic in make.
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

// str reads a length-prefixed, UTF-8-validated string.
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
