package vcffi

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// A ciphertext is made of ordinary Go values — the same dynamic shape as
// decoded plaintext — with marker types distinguishing what is sealed from
// what travels in the clear:
//
//   - a sealed-leaf marker (one of the binding's [LeafSet] types, e.g.
//     vcvalue.Sealed): one encrypted leaf, an authenticated absent marker,
//     or an authenticated empty-composite marker
//   - vcvalue.Plain{V: ...}: a passthrough field, readable without the key
//   - []any: a sequence of ciphertext nodes
//   - map[string]any: a record of named nodes. Keys travel in the clear but
//     each is cryptographically bound to its sealed value — renaming or
//     swapping keys fails decryption. Entry order is not authenticated
//     (encoding sorts keys for determinism), and there is no whole-map seal:
//     any subset of entries decrypts independently.
//
// There is deliberately no dedicated tree type and no conversion step: a
// map-shaped ciphertext binds directly as database named parameters (the leaf
// types and vcvalue.Plain implement driver.Valuer), and leaves loaded back
// from columns go into a map[string]any for decryption. Only the sealed leaf
// bytes are a frozen format; the transport encoding crossing the FFI boundary
// is an implementation detail.
//
// Which concrete leaf types appear in the tree is the one thing this codec
// does not decide: each binding supplies a [LeafSet] so its leaves stay a
// distinct Go type. A stack-encrypt sealed leaf is not decryptable by
// vitaminc-encrypt, and keeping the types distinct means one can never scan
// or marshal where the other belongs.

// Ciphertext node tags in the transport encoding (mirrors the Rust codec).
// 0x02 was the absent marker, retired by ADR 0001 (a None is a null leaf):
// never written, and refused when read like any unknown tag.
const (
	ctSingle      byte = 0x01
	ctSeq         byte = 0x03
	ctMap         byte = 0x04
	ctPassthrough byte = 0x05
	ctEmptySeq    byte = 0x06
	ctEmptyMap    byte = 0x07
)

// LeafKind names the three sealed-leaf node kinds of the ciphertext framing.
// The stored bytes do not record the kind — it is authenticated through
// domain-separated AAD — so the framing carries it on the wire.
type LeafKind byte

const (
	// LeafSingle is one encrypted value.
	LeafSingle LeafKind = iota
	// LeafEmptySeq is the authenticated marker for an empty sequence.
	LeafEmptySeq
	// LeafEmptyMap is the authenticated marker for an empty map.
	LeafEmptyMap
)

// LeafSet maps a binding's sealed-leaf marker types onto the ciphertext
// framing, in both directions. Each binding defines its own leaf types (so a
// leaf sealed by one cipher can never be mistaken for another's) and hands
// the codec this pair of translations:
//
//   - Classify reports whether v is one of the binding's leaf values,
//     returning its kind and bytes. The codec's structural node types
//     ([]any, map[string]any, vcvalue.Plain) are never offered to Classify,
//     so a LeafSet cannot claim a subtree; values Classify does not claim
//     fall through to the bare-plaintext rejection.
//   - Make constructs the binding's leaf value for a kind decoded off the
//     wire. The bytes slice is freshly allocated and owned by the callee.
//     Returning nil rejects the kind: the decoder turns it into an error, so
//     a LeafSet that materializes only some kinds fails loudly instead of
//     injecting nil nodes into the decoded tree.
//
// [VCValueLeaves] is the set for the vcvalue model types.
type LeafSet struct {
	Classify func(v any) (LeafKind, []byte, bool)
	Make     func(kind LeafKind, bytes []byte) any
}

// VCValueLeaves returns the [LeafSet] of the vcvalue model: vcvalue.Sealed,
// vcvalue.SealedEmptySeq and vcvalue.SealedEmptyMap.
// These are the leaf types the vitaminc-encrypt binding materializes; other
// bindings define their own set so their leaves stay a distinct Go type. A
// function rather than an exported var, so no importer can reassign the set
// out from under every other consumer in the process.
func VCValueLeaves() LeafSet {
	return vcValueLeaves
}

var vcValueLeaves = LeafSet{
	Classify: func(v any) (LeafKind, []byte, bool) {
		switch n := v.(type) {
		case vcvalue.Sealed:
			return LeafSingle, n, true
		case vcvalue.SealedEmptySeq:
			return LeafEmptySeq, n, true
		case vcvalue.SealedEmptyMap:
			return LeafEmptyMap, n, true
		default:
			return 0, nil, false
		}
	},
	Make: func(kind LeafKind, bytes []byte) any {
		switch kind {
		case LeafSingle:
			return vcvalue.Sealed(bytes)
		case LeafEmptySeq:
			return vcvalue.SealedEmptySeq(bytes)
		case LeafEmptyMap:
			return vcvalue.SealedEmptyMap(bytes)
		default:
			// An unlisted kind is rejected (nil), mirroring leafTag on the
			// encode side — a future fourth kind must not silently mint Sealed.
			return nil
		}
	},
}

// check rejects a partially wired LeafSet up front, where the mistake is
// attributable, instead of as a nil-function panic mid-tree.
func (l LeafSet) check() error {
	if l.Classify == nil || l.Make == nil {
		return errors.New("vcffi: LeafSet must define both Classify and Make")
	}
	return nil
}

// leafTags is the single source of truth for the LeafKind ↔ wire-tag
// correspondence; leafTag and leafKind are its two directions, so a new leaf
// kind cannot be wired into one direction and missed in the other.
//
// No ciphertext tag is 0x00, so a zero entry means "this kind is not wired to
// the wire format" — a hole left by a LeafKind constant that skips a value,
// or an index past the end. Both directions refuse it, so a kind can never
// round-trip inside Go under a tag the Rust codec has never heard of.
var leafTags = [...]byte{
	LeafSingle:   ctSingle,
	LeafEmptySeq: ctEmptySeq,
	LeafEmptyMap: ctEmptyMap,
}

// leafTag maps a classified kind to its wire tag.
func leafTag(kind LeafKind) (byte, error) {
	if int(kind) >= len(leafTags) || leafTags[kind] == 0 {
		return 0, fmt.Errorf("vcffi: LeafSet classified an unknown LeafKind %d", kind)
	}
	return leafTags[kind], nil
}

// leafKind maps a wire tag back to its leaf kind — the decode direction.
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

// MarshalCipherText encodes a ciphertext value into transport bytes; leaves
// recognizes the binding's sealed-leaf types. Bare plaintext values are
// rejected — a passthrough must be marked with vcvalue.Plain, so a value can
// never end up travelling unencrypted by accident.
func MarshalCipherText(leaves LeafSet, v any) ([]byte, error) {
	if err := leaves.check(); err != nil {
		return nil, err
	}
	return encodeCipherText(leaves, nil, v, 0)
}

// UnmarshalCipherText decodes a transport-encoded ciphertext into the dynamic
// shape above — leaf nodes constructed through leaves — requiring the whole
// buffer to be consumed.
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
	// The structural arms come first: the codec's own node types are never
	// offered to Classify, so a LeafSet cannot claim a whole subtree as one
	// leaf chunk — only non-structural values reach it (in the default arm).
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
	case vcvalue.Plain:
		// The payload node sits one level deeper; reject it here because the
		// value encoder's scalar channels never re-check depth, and emitting
		// bytes the decoder is guaranteed to reject (decodeValue enforces the
		// same bound) would be an asymmetric round trip.
		if depth+1 > maxDepth {
			return nil, ErrTooDeep
		}
		out = append(out, ctPassthrough)
		// Encode the plaintext payload as one value node, sharing the
		// recursion budget with the surrounding ciphertext (depth+1),
		// mirroring the Rust CT_PASSTHROUGH framing.
		st := &encState{buf: out}
		var done int
		encodeAny(Encoder{st: st, depth: depth + 1, done: &done}, n.V)
		if st.err != nil {
			return nil, st.err
		}
		if done != 1 {
			return nil, fmt.Errorf("vcffi: passthrough payload must complete exactly one value, completed %d", done)
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
		return nil, fmt.Errorf("vcffi: %T is not a ciphertext node — wrap passthrough values in vcvalue.Plain", v)
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
			// A LeafSet that does not materialize this kind is a wiring
			// mistake in the binding, not malformed input — name it, instead
			// of injecting a nil node the caller only trips over later.
			return nil, fmt.Errorf("vcffi: LeafSet.Make returned no value for LeafKind %d", kind)
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
		// One embedded plaintext value node, decoded one level deeper.
		v, err := decodeValue(r, depth+1)
		if err != nil {
			return nil, err
		}
		return vcvalue.Plain{V: v}, nil
	default:
		return nil, ErrMalformed
	}
}
