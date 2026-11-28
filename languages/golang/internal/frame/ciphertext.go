package frame

import (
	"errors"
	"fmt"
	"slices"
)

// A ciphertext is a tree of ordinary Go values, with the same structure as a
// decoded plaintext. Marker types show which parts are sealed and which are
// passthrough. A node is one of these:
//
//   - A sealed leaf, of one of the caller's [LeafSet] types. A sealed leaf
//     is one encrypted value, an authenticated marker for an absent value,
//     or an authenticated marker for an empty sequence or map.
//   - Plain{V: ...}, a passthrough value. Anyone can read it without the
//     key.
//   - []any, a sequence of ciphertext nodes.
//   - map[string]any, a record of named nodes.
//
// The keys of a map are not encrypted. Each key is cryptographically bound
// to its sealed value, so decryption fails if a key is renamed or two keys
// are swapped. The order of the entries is not authenticated. The encoder
// writes the keys in sorted order, so equal maps have equal bytes. The map
// as a whole is not sealed: any subset of its entries decrypts without the
// rest.
//
// The package deliberately has no type for the tree. Only the bytes of a
// sealed leaf are a format that never changes. The transport bytes that
// cross into and out of the guest are an implementation detail.
//
// The codec does not decide which Go types are leaves. The caller supplies a
// [LeafSet], so that a leaf has a distinct Go type. A value that is not a
// leaf therefore cannot be scanned or marshaled in the place of a leaf.

// The tags of the nodes in the ciphertext encoding. The Rust codec uses the
// same values. The value 0x02 is not a tag, because an absent value is a
// sealed null leaf. The encoder never writes 0x02. The decoder refuses it,
// as it refuses any unknown tag.
const (
	ctSingle      byte = 0x01
	ctSeq         byte = 0x03
	ctMap         byte = 0x04
	ctPassthrough byte = 0x05
	ctEmptySeq    byte = 0x06
	ctEmptyMap    byte = 0x07
)

// LeafKind is one of the three kinds of sealed leaf in the ciphertext
// encoding. The stored bytes of a leaf do not record its kind. The kind is
// authenticated through the additional authenticated data (AAD) of the leaf.
// Each kind has a different AAD. The ciphertext encoding therefore records
// the kind in the tag.
type LeafKind byte

const (
	// LeafSingle is one encrypted value.
	LeafSingle LeafKind = iota
	// LeafEmptySeq is the authenticated marker for an empty sequence.
	LeafEmptySeq
	// LeafEmptyMap is the authenticated marker for an empty map.
	LeafEmptyMap
)

// LeafSet converts between the caller's sealed-leaf types and the leaves of
// the ciphertext encoding, in both directions. The caller defines its own
// leaf types, so a leaf that one cipher sealed is never used as the leaf of
// another. The caller gives the codec two functions:
//
//   - Classify reports whether v is one of the caller's leaf values. If v is
//     one, Classify returns its kind and its bytes. The codec never passes
//     one of its own node types to Classify: []any, map[string]any, or
//     Plain. A LeafSet therefore cannot treat a subtree as one leaf. The
//     encoder refuses a value that Classify does not accept, as plaintext
//     that is not marked.
//   - Make builds the caller's leaf value for a kind that the decoder read.
//     The byte slice is newly allocated, and Make owns it. Make returns nil
//     to refuse the kind. The decoder then returns an error. A LeafSet that
//     builds only some kinds therefore fails with an error, and never puts a
//     nil node into the decoded tree.
type LeafSet struct {
	Classify func(v any) (LeafKind, []byte, bool)
	Make     func(kind LeafKind, bytes []byte) any
}

// check refuses a LeafSet that has a nil function. The check runs before the
// codec encodes or decodes anything. The error then names the mistake.
// Without check, the mistake would be a nil-function panic part of the way
// through a tree.
func (l LeafSet) check() error {
	if l.Classify == nil || l.Make == nil {
		return errors.New("frame: LeafSet must define both Classify and Make")
	}
	return nil
}

// leafTags is the only table that pairs a LeafKind with its tag. The
// functions leafTag and leafKind read it, one in each direction. A new kind
// of leaf therefore cannot be added to one direction and left out of the
// other.
//
// No ciphertext tag is 0x00, so a zero entry means that the kind has no tag.
// A zero entry appears when the LeafKind constants skip a value. An index
// past the end of the table has no tag either. Both leafTag and leafKind
// refuse such a kind. Go therefore never encodes and decodes a kind with a
// tag that the Rust codec does not know.
var leafTags = [...]byte{
	LeafSingle:   ctSingle,
	LeafEmptySeq: ctEmptySeq,
	LeafEmptyMap: ctEmptyMap,
}

// leafTag returns the tag for a kind that Classify returned.
func leafTag(kind LeafKind) (byte, error) {
	if int(kind) >= len(leafTags) || leafTags[kind] == 0 {
		return 0, fmt.Errorf("frame: LeafSet classified an unknown LeafKind %d", kind)
	}
	return leafTags[kind], nil
}

// leafKind returns the kind of leaf for a tag. The decoder uses it.
func leafKind(tag byte) (LeafKind, bool) {
	if tag == 0 {
		return 0, false
	}
	for kind, t := range leafTags {
		if t == tag {
			return LeafKind(kind), true
		}
	}
	return 0, false
}

// MarshalCipherText encodes a ciphertext tree as transport bytes. The leaves
// argument identifies the caller's sealed-leaf types. MarshalCipherText
// refuses a plaintext value that is not marked. A passthrough value must be
// wrapped in Plain, so no value is left unencrypted by accident.
func MarshalCipherText(leaves LeafSet, v any) ([]byte, error) {
	if err := leaves.check(); err != nil {
		return nil, err
	}
	return encodeCipherText(leaves, nil, v, 0)
}

// UnmarshalCipherText decodes the transport bytes of a ciphertext into the
// tree of Go values described above. The Make function of leaves builds each
// leaf node. UnmarshalCipherText returns ErrMalformed if any bytes are left
// after the tree.
func UnmarshalCipherText(leaves LeafSet, buf []byte) (any, error) {
	if err := leaves.check(); err != nil {
		return nil, err
	}
	r := &reader{buf: buf}
	ct, err := decodeCipherText(leaves, r, 0)
	if err != nil {
		return nil, err
	}
	if !r.finished() {
		return nil, ErrMalformed
	}
	return ct, nil
}

func encodeCipherText(leaves LeafSet, out []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, ErrTooDeep
	}
	// The cases for the codec's own node types come first, so Classify never
	// receives one of them. A LeafSet therefore cannot treat a whole subtree
	// as one leaf. Only the default case calls Classify.
	switch n := v.(type) {
	case []any:
		out = append(out, ctSeq)
		out, err := appendLen(out, len(n))
		if err != nil {
			return nil, err
		}
		for _, item := range n {
			if out, err = encodeCipherText(leaves, out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case map[string]any:
		out = append(out, ctMap)
		out, err := appendLen(out, len(n))
		if err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if out, err = appendChunk(out, []byte(k)); err != nil {
				return nil, err
			}
			if out, err = encodeCipherText(leaves, out, n[k], depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case Plain:
		// The value inside a Plain is one level deeper. Refuse it here if
		// that level is too deep, because the scalar methods of the value
		// encoder do not check the depth. The decoder applies the same limit
		// in decodeValue. Without this check, the encoder would write bytes
		// that the decoder always refuses.
		if depth+1 > maxDepth {
			return nil, ErrTooDeep
		}
		out = append(out, ctPassthrough)
		// Encode the plaintext value as one value node. The node counts
		// against the same depth limit as the ciphertext around it, at
		// depth+1. The Rust codec encodes CT_PASSTHROUGH the same way.
		st := &encState{buf: out}
		var done int
		encodeAny(Encoder{st: st, depth: depth + 1, done: &done}, n.V)
		if st.err != nil {
			return nil, st.err
		}
		if done != 1 {
			return nil, fmt.Errorf("frame: passthrough payload must complete exactly one value, completed %d", done)
		}
		return st.buf, nil
	default:
		if kind, bytes, ok := leaves.Classify(v); ok {
			tag, err := leafTag(kind)
			if err != nil {
				return nil, err
			}
			out = append(out, tag)
			return appendChunk(out, bytes)
		}
		return nil, fmt.Errorf("frame: %T is not a ciphertext node — wrap passthrough values in Plain", v)
	}
}

func decodeCipherText(leaves LeafSet, r *reader, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrMalformed
	}
	tag, err := r.byteTag()
	if err != nil {
		return nil, err
	}
	if kind, ok := leafKind(tag); ok {
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		s, err := r.take(n)
		if err != nil {
			return nil, err
		}
		leaf := make([]byte, len(s))
		copy(leaf, s)
		node := leaves.Make(kind, leaf)
		if node == nil {
			// A LeafSet that builds no value for this kind is a mistake in
			// the caller. The input is not malformed, so the error names the
			// mistake. A nil node in the tree would fail only later,
			// somewhere in the caller's code.
			return nil, fmt.Errorf("frame: LeafSet.Make returned no value for LeafKind %d", kind)
		}
		return node, nil
	}
	switch tag {
	case ctSeq:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, eagerCap(n))
		for range n {
			item, err := decodeCipherText(leaves, r, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case ctMap:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		fields := make(map[string]any, eagerCap(n))
		for range n {
			key, err := r.str()
			if err != nil {
				return nil, err
			}
			if _, dup := fields[key]; dup {
				return nil, ErrMalformed
			}
			node, err := decodeCipherText(leaves, r, depth+1)
			if err != nil {
				return nil, err
			}
			fields[key] = node
		}
		return fields, nil
	case ctPassthrough:
		// A passthrough node contains one plaintext value node. The value is
		// decoded one level deeper.
		v, err := decodeValue(r, depth+1)
		if err != nil {
			return nil, err
		}
		return Plain{V: v}, nil
	default:
		return nil, ErrMalformed
	}
}
