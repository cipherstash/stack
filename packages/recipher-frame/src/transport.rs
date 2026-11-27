//! Transport-only binary encoding for ciphertext trees crossing an FFI
//! boundary (e.g. the Go/WASI binding's wasm linear-memory copy). The
//! value side of the transport is the frame ([`Frame`],
//! [`FrameWriter`](vitaminc_aead::FrameWriter)),
//! which lives in `vitaminc-aead` next to the leaf codec it shares.
//!
//! This is a **transport encoding, not a storage format**: it exists so a
//! host language and a guest can hand each other a tree in one linear-memory
//! copy. This encoding has no stability guarantee. For versioned value blobs,
//! use the storage profile (`storage`, enabled by the `serde` feature).
//! The sealed leaf payload (`[tag] ++ payload`, see
//! [`tags`](vitaminc_aead::tags)) is also a stable format; it lives inside
//! the AEAD envelope and is separate from this codec.
//!
//! A ciphertext node is one byte of kind, then its payload: a sealed leaf
//! as `u32` length and bytes, a container as `u32` count and children, a
//! map entry as `u32` key length, key bytes and child, and a passthrough as
//! the frame of its subtree. The kinds use `0x01`–`0x07`; `0x02` was the
//! retired `CT_NONE` absence marker. It is never written and is rejected
//! when read; `None` is encoded as a null leaf.
//!
//! All lengths and counts are `u32` little-endian. Map keys are UTF-8.
//!
//! Both directions are attacker-reachable input, and both enforce the same
//! rules: the encoder refuses what the decoder would refuse (a tree deeper
//! than [`MAX_DEPTH`], a duplicate map key, a passthrough payload that is
//! not exactly one frame node, the retired marker), so anything it writes
//! decodes, and it writes nothing for a refused tree.

use std::collections::HashSet;

use vitaminc_aead::{CipherText, Frame, Node, PassthroughFrame};

// The framing tags and the depth bound live with the frame in
// `vitaminc_aead::frame`, so this codec and the frame cannot drift apart.
pub use vitaminc_aead::frame::{ARRAY, MAX_DEPTH, OBJECT, PASSTHROUGH};

/// A single sealed leaf.
pub const CT_SINGLE: u8 = 0x01;
/// A sequence of child nodes.
pub const CT_SEQ: u8 = 0x03;
/// A map of key → child node.
pub const CT_MAP: u8 = 0x04;
/// A passthrough node: the frame of an unencrypted subtree.
pub const CT_PASSTHROUGH: u8 = 0x05;
/// An authenticated empty-sequence marker.
pub const CT_EMPTY_SEQ: u8 = 0x06;
/// An authenticated empty-map marker.
pub const CT_EMPTY_MAP: u8 = 0x07;

/// The retired absence marker. Kept out of the public table so nothing can
/// write it; the decoder refuses it like any unknown kind. Named here only
/// so the tests can say which byte they are refusing.
#[cfg(test)]
const CT_NONE_RETIRED: u8 = 0x02;

/// A passthrough payload is a [`PassthroughFrame`], already one value node,
/// so it crosses the transport as its own bytes. The field is public, so a
/// hand-built payload could hold no node, two, or a truncated one, and
/// would misframe the siblings after it; the encoder validates it as one
/// frame at the ciphertext's depth, with nothing left over, before writing.
fn encode_passthrough(
    payload: &PassthroughFrame,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), CodecError> {
    let (_, rest) = Frame::parse_nested(&payload.0, depth).map_err(|_| CodecError)?;
    if !rest.is_empty() {
        return Err(CodecError);
    }
    out.extend_from_slice(&payload.0);
    Ok(())
}

/// Read one frame node at the ciphertext's depth and take exactly it.
fn decode_passthrough(
    reader: &mut Reader<'_>,
    depth: usize,
) -> Result<PassthroughFrame, CodecError> {
    let (frame, _) = Frame::parse_nested(reader.remaining(), depth).map_err(|_| CodecError)?;
    let len = frame.as_bytes().len();
    Ok(PassthroughFrame(reader.take(len)?.to_vec()))
}

/// Opaque codec error. Like the trait-layer `Unspecified`, it carries no
/// detail: malformed transport bytes on the decrypt path are
/// attacker-reachable input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecError;

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Fixed, so the message carries no detail about the bytes.
        f.write_str("malformed ciphertext transport")
    }
}

impl std::error::Error for CodecError {}

/// Cursor over a transport buffer.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        let b = *self.buf.get(self.pos).ok_or(CodecError)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(len).ok_or(CodecError)?;
        let slice = self.buf.get(self.pos..end).ok_or(CodecError)?;
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| CodecError)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// The bytes not yet consumed.
    fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// A count of items (or a byte length) still to be decoded can never
    /// exceed the bytes remaining — every item costs at least one byte, and a
    /// byte length costs exactly itself. Rejecting early keeps a hostile count
    /// from driving a huge preallocation.
    ///
    /// Phrased against the remaining slice's length rather than
    /// `len - pos`: arithmetic on the two cursors admits an off-by-one that no
    /// input can distinguish (a too-large count that slips past the guard
    /// still fails when the reader runs dry, so only the transient allocation
    /// differs), whereas this form is exercised by every decode.
    fn count(&mut self) -> Result<usize, CodecError> {
        let n = self.u32()? as usize;
        if n > self.remaining().len() {
            return Err(CodecError);
        }
        Ok(n)
    }

    fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Clamp for the *eager* part of a count-driven preallocation.
///
/// [`Reader::count`] already rejects counts exceeding the bytes remaining,
/// but that guard bounds a single reservation, not the *sum* of live
/// reservations: a container nesting level costs 5–9 wire bytes while a
/// reserved element slot costs ~28, and up to [`MAX_DEPTH`] ancestor
/// reservations are live at once — so ~1 MB of hostile bytes could otherwise
/// pin gigabytes of reservations and abort the allocator (uncatchable in the
/// wasm guest). Same hazard and clamp as `aead-napi`'s `MAX_EAGER_CAPACITY`.
/// Vectors still grow past the clamp on push; only the up-front reservation
/// is bounded.
const MAX_EAGER_CAPACITY: usize = 1024;

fn eager_capacity(count: usize) -> usize {
    count.min(MAX_EAGER_CAPACITY)
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), CodecError> {
    let len: u32 = len.try_into().map_err(|_| CodecError)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    write_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_key(reader: &mut Reader<'_>) -> Result<String, CodecError> {
    let len = reader.count()?;
    let bytes = reader.take(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| CodecError)
}

/// Encode a ciphertext tree. A `Passthrough` node carries its payload as one
/// embedded frame. The tree is held to the decoder's rules, so what is
/// written always decodes: a tree nested deeper than [`MAX_DEPTH`], a map
/// with a duplicate key and a passthrough payload that is not one frame
/// node are refused, and `out` is left as it was. The retired `None`
/// marker has no node to be written from: a `None` is a null leaf.
pub fn encode_ciphertext<Leaf>(ct: &Node<Leaf>, out: &mut Vec<u8>) -> Result<(), CodecError>
where
    Leaf: AsRef<[u8]>,
{
    let start = out.len();
    encode_ciphertext_inner(ct, out, 0).inspect_err(|_| out.truncate(start))
}

fn encode_ciphertext_inner<Leaf>(
    ct: &Node<Leaf>,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), CodecError>
where
    Leaf: AsRef<[u8]>,
{
    if depth > MAX_DEPTH {
        return Err(CodecError);
    }
    match ct {
        CipherText::Single(leaf) => {
            out.push(CT_SINGLE);
            write_bytes(out, leaf.as_ref())?;
        }
        CipherText::EmptySequence(leaf) => {
            out.push(CT_EMPTY_SEQ);
            write_bytes(out, leaf.as_ref())?;
        }
        CipherText::EmptyMap(leaf) => {
            out.push(CT_EMPTY_MAP);
            write_bytes(out, leaf.as_ref())?;
        }
        CipherText::Sequence(items) => {
            out.push(CT_SEQ);
            write_len(out, items.len())?;
            for item in items {
                encode_ciphertext_inner(item, out, depth + 1)?;
            }
        }
        CipherText::Map(entries) => {
            out.push(CT_MAP);
            write_len(out, entries.len())?;
            let mut seen: HashSet<&str> = HashSet::with_capacity(eager_capacity(entries.len()));
            for (key, value) in entries {
                // Mirror of the decoder's duplicate-key rejection.
                if !seen.insert(key.as_str()) {
                    return Err(CodecError);
                }
                write_bytes(out, key.as_bytes())?;
                encode_ciphertext_inner(value, out, depth + 1)?;
            }
        }
        CipherText::Passthrough(payload) => {
            out.push(CT_PASSTHROUGH);
            // One level deeper, as the decoder reads it.
            encode_passthrough(payload, out, depth + 1)?;
        }
    }
    Ok(())
}

/// Decode a ciphertext tree. The tree must use every byte: trailing bytes
/// are refused.
pub fn decode_ciphertext<Leaf>(bytes: &[u8]) -> Result<Node<Leaf>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    let mut reader = Reader::new(bytes);
    let ct = decode_ciphertext_inner(&mut reader, 0)?;
    if !reader.finished() {
        return Err(CodecError);
    }
    Ok(ct)
}

fn decode_ciphertext_inner<Leaf>(
    reader: &mut Reader<'_>,
    depth: usize,
) -> Result<Node<Leaf>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    if depth > MAX_DEPTH {
        return Err(CodecError);
    }
    match reader.byte()? {
        CT_SEQ => {
            let count = reader.count()?;
            let mut items = Vec::with_capacity(eager_capacity(count));
            for _ in 0..count {
                items.push(decode_ciphertext_inner(reader, depth + 1)?);
            }
            Ok(CipherText::Sequence(items))
        }
        CT_MAP => {
            let count = reader.count()?;
            let mut entries = Vec::with_capacity(eager_capacity(count));
            let mut seen: HashSet<String> = HashSet::with_capacity(eager_capacity(count));
            for _ in 0..count {
                let key = decode_key(reader)?;
                // Mirror of the frame's duplicate-key rejection.
                if !seen.insert(key.clone()) {
                    return Err(CodecError);
                }
                entries.push((key, decode_ciphertext_inner(reader, depth + 1)?));
            }
            Ok(CipherText::Map(entries))
        }
        CT_PASSTHROUGH => {
            // The payload is one frame, decoded one level deeper so a
            // hostile nesting through passthrough stays bounded.
            Ok(CipherText::Passthrough(decode_passthrough(
                reader,
                depth + 1,
            )?))
        }
        tag => decode_ciphertext_leaf(tag, reader),
    }
}

/// Decode a leaf-shaped ciphertext node — the three variants that carry one
/// sealed byte string and no children. Split out of
/// [`decode_ciphertext_inner`] so neither function carries every branch.
fn decode_ciphertext_leaf<Leaf>(tag: u8, reader: &mut Reader<'_>) -> Result<Node<Leaf>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    // Every leaf variant is framed identically; only the variant differs.
    let wrap: fn(Leaf) -> Node<Leaf> = match tag {
        CT_SINGLE => CipherText::Single,
        CT_EMPTY_SEQ => CipherText::EmptySequence,
        CT_EMPTY_MAP => CipherText::EmptyMap,
        // Unknown kinds, including the retired absence marker `0x02`
        // (`CT_NONE`): a `None` is a null leaf now.
        _ => return Err(CodecError),
    };
    let len = reader.count()?;
    Ok(wrap(Leaf::from(reader.take(len)?.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;
    use vitaminc_aead::tags;

    type Ct = Node<Vec<u8>>;

    fn leaf(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    /// A frame of `n` arrays around null.
    fn frame(n: usize) -> PassthroughFrame {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(ARRAY);
            bytes.extend_from_slice(&1u32.to_le_bytes());
        }
        bytes.push(tags::NULL);
        PassthroughFrame(bytes)
    }

    fn encode(ct: &Ct) -> Vec<u8> {
        let mut out = Vec::new();
        encode_ciphertext(ct, &mut out).expect("codec");
        out
    }

    fn decode(bytes: &[u8]) -> Result<Ct, CodecError> {
        decode_ciphertext(bytes)
    }

    /// Round-trip a ciphertext tree and return the decoded tree, asserting
    /// the encoding is stable across the trip.
    fn round_trip(ct: Ct) -> Ct {
        let out = encode(&ct);
        let decoded = decode(&out).expect("codec");
        assert_eq!(encode(&decoded), out, "re-encode must be byte-stable");
        decode(&out).expect("codec")
    }

    #[test]
    fn a_tree_round_trips() {
        let ct: Ct = CipherText::Map(vec![
            ("a".into(), CipherText::Single(leaf(9, 40))),
            (
                "b".into(),
                CipherText::Sequence(vec![
                    CipherText::Single(leaf(1, 3)),
                    CipherText::Passthrough(frame(1)),
                    CipherText::EmptyMap(leaf(2, 3)),
                ]),
            ),
        ]);
        let back = round_trip(ct);
        let CipherText::Map(entries) = back else {
            panic!("a map decodes as a map");
        };
        assert_eq!(entries.len(), 2);
        assert!(matches!(&entries[1].1, CipherText::Sequence(items) if items.len() == 3));
    }

    #[test]
    fn every_leaf_variant_round_trips_as_itself() {
        // The leaf-shaped nodes are framed identically, so only the tag
        // distinguishes them: a dropped or swapped arm would decode one as
        // another. Check each lands on its own variant with its bytes.
        let bytes = leaf(7, 40);
        match round_trip(CipherText::Single(bytes.clone())) {
            CipherText::Single(l) => assert_eq!(l, bytes),
            other => panic!("expected Single, got {other:?}"),
        }
        match round_trip(CipherText::EmptySequence(bytes.clone())) {
            CipherText::EmptySequence(l) => assert_eq!(l, bytes),
            other => panic!("expected EmptySequence, got {other:?}"),
        }
        match round_trip(CipherText::EmptyMap(bytes.clone())) {
            CipherText::EmptyMap(l) => assert_eq!(l, bytes),
            other => panic!("expected EmptyMap, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_tree_leaves_the_output_untouched() {
        // Nested below a sibling that was already written, the output is
        // put back as it was, including what the caller had in it.
        let mut out = vec![0xEE];
        let nested: Ct = CipherText::Sequence(vec![
            CipherText::Single(leaf(1, 2)),
            CipherText::Map(vec![
                ("k".into(), CipherText::Single(leaf(1, 1))),
                ("k".into(), CipherText::Single(leaf(2, 1))),
            ]),
        ]);
        assert_eq!(encode_ciphertext(&nested, &mut out), Err(CodecError));
        assert_eq!(out, [0xEE], "a refused tree leaves the output untouched");
    }

    #[test]
    fn the_retired_none_marker_is_refused_when_read() {
        let mut bytes = vec![CT_NONE_RETIRED];
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[1; 4]);
        assert!(decode(&bytes).is_err());
        // Inside a container too, and the kinds around it still decode.
        let mut seq = vec![CT_SEQ, 1, 0, 0, 0];
        seq.extend_from_slice(&bytes);
        assert!(decode(&seq).is_err());
        let ok = encode(&CipherText::Sequence(vec![CipherText::Single(leaf(1, 4))]));
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn the_kinds_are_pinned() {
        assert_eq!(
            encode(&CipherText::Single(leaf(0xAB, 1))),
            [CT_SINGLE, 1, 0, 0, 0, 0xAB]
        );
        assert_eq!(
            encode(&CipherText::EmptySequence(leaf(0xAB, 1))),
            [CT_EMPTY_SEQ, 1, 0, 0, 0, 0xAB]
        );
        assert_eq!(
            encode(&CipherText::EmptyMap(leaf(0xAB, 1))),
            [CT_EMPTY_MAP, 1, 0, 0, 0, 0xAB]
        );
        assert_eq!(
            encode(&CipherText::Sequence(vec![CipherText::Single(leaf(
                0xAB, 1
            ))])),
            [CT_SEQ, 1, 0, 0, 0, CT_SINGLE, 1, 0, 0, 0, 0xAB]
        );
        assert_eq!(
            encode(&CipherText::Map(vec![(
                "k".into(),
                CipherText::Single(leaf(0xAB, 1))
            )])),
            [CT_MAP, 1, 0, 0, 0, 1, 0, 0, 0, b'k', CT_SINGLE, 1, 0, 0, 0, 0xAB]
        );
        // A passthrough is the kind byte then the frame, as the frame is.
        assert_eq!(
            encode(&CipherText::Passthrough(frame(0))),
            [CT_PASSTHROUGH, tags::NULL]
        );
        assert_eq!(
            [
                CT_SINGLE,
                CT_SEQ,
                CT_MAP,
                CT_PASSTHROUGH,
                CT_EMPTY_SEQ,
                CT_EMPTY_MAP
            ],
            [0x01, 0x03, 0x04, 0x05, 0x06, 0x07]
        );
    }

    #[test]
    fn duplicate_map_keys_are_refused() {
        fn ct_map(keys: [&str; 2]) -> Vec<u8> {
            let mut bytes = vec![CT_MAP, 2, 0, 0, 0];
            for key in keys {
                bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
                bytes.extend_from_slice(key.as_bytes());
                bytes.push(CT_SINGLE);
                bytes.extend_from_slice(&1u32.to_le_bytes());
                bytes.push(0xAB);
            }
            bytes
        }
        assert!(decode(&ct_map(["k", "k"])).is_err());
        assert!(decode(&ct_map(["k", "l"])).is_ok());
    }

    #[test]
    fn map_keys_are_read_per_entry() {
        // Differently-sized keys in one map: an arithmetic slip in the key
        // framing desynchronises the reader.
        let ct: Ct = CipherText::Map(vec![
            ("a".into(), CipherText::Single(leaf(1, 4))),
            ("bcd".into(), CipherText::Single(leaf(2, 4))),
        ]);
        match round_trip(ct) {
            CipherText::Map(entries) => {
                let keys: Vec<_> = entries.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, vec!["a", "bcd"]);
            }
            other => panic!("expected Map, got {other:?}"),
        }
        // A key that is not UTF-8 is refused.
        let bytes = [
            CT_MAP, 1, 0, 0, 0, 1, 0, 0, 0, 0xFF, CT_SINGLE, 1, 0, 0, 0, 0xAB,
        ];
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn counts_are_bounded_by_the_bytes_remaining() {
        // A count that would fit in the whole buffer but not in the
        // remainder is refused before anything is reserved.
        let bytes = [CT_SEQ, 3, 0, 0, 0, CT_SINGLE, 0, 0, 0, 0];
        assert!(decode(&bytes).is_err());
        let ok = [CT_SEQ, 1, 0, 0, 0, CT_SINGLE, 0, 0, 0, 0];
        assert!(decode(&ok).is_ok());
        // A leaf length past the end, and trailing bytes, are refused too.
        assert!(decode(&[CT_SINGLE, 2, 0, 0, 0, 0xAB]).is_err());
        assert!(decode(&[CT_SINGLE, 1, 0, 0, 0, 0xAB, 0xCD]).is_err());
        assert!(decode(&[]).is_err());
        assert_eq!(eager_capacity(MAX_EAGER_CAPACITY + 1), MAX_EAGER_CAPACITY);
        assert_eq!(eager_capacity(3), 3);
    }

    /// Wrap a leaf in `n` nested single-element sequences.
    fn nested_seq(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(CT_SEQ);
            bytes.extend_from_slice(&1u32.to_le_bytes());
        }
        bytes.extend_from_slice(&[CT_SINGLE, 1, 0, 0, 0, 0xAB]);
        bytes
    }

    /// Wrap a leaf in `n` nested single-entry maps.
    fn nested_map(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(CT_MAP);
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(b'k');
        }
        bytes.extend_from_slice(&[CT_SINGLE, 1, 0, 0, 0, 0xAB]);
        bytes
    }

    #[test]
    fn depth_is_bounded_for_every_container() {
        assert!(decode(&nested_seq(MAX_DEPTH)).is_ok());
        assert!(decode(&nested_seq(MAX_DEPTH + 1)).is_err());
        assert!(decode(&nested_map(MAX_DEPTH)).is_ok());
        assert!(decode(&nested_map(MAX_DEPTH + 1)).is_err());
    }

    /// A leaf under `n` nested single-child containers, as a tree: a
    /// sequence or a map at each level.
    fn nested_tree(n: usize, map: bool) -> Ct {
        let mut ct: Ct = CipherText::Single(leaf(0xAB, 1));
        for _ in 0..n {
            ct = if map {
                CipherText::Map(vec![("k".into(), ct)])
            } else {
                CipherText::Sequence(vec![ct])
            };
        }
        ct
    }

    #[test]
    fn the_encoder_refuses_what_the_decoder_would() {
        // Depth: the bound counts the same way in both directions, for
        // every container kind.
        for map in [false, true] {
            let mut out = Vec::new();
            assert!(encode_ciphertext(&nested_tree(MAX_DEPTH, map), &mut out).is_ok());
            assert!(decode(&out).is_ok());
            let mut out = Vec::new();
            assert_eq!(
                encode_ciphertext(&nested_tree(MAX_DEPTH + 1, map), &mut out),
                Err(CodecError)
            );
            assert!(out.is_empty());
        }
        // A passthrough payload shares the budget on the way in too.
        let mut out = Vec::new();
        let ok: Ct = CipherText::Passthrough(frame(MAX_DEPTH - 1));
        assert!(encode_ciphertext(&ok, &mut out).is_ok());
        assert!(decode(&out).is_ok());
        let mut out = Vec::new();
        let too_deep: Ct = CipherText::Passthrough(frame(MAX_DEPTH));
        assert_eq!(encode_ciphertext(&too_deep, &mut out), Err(CodecError));
        assert!(out.is_empty());
        // Duplicate map keys.
        let dup: Ct = CipherText::Map(vec![
            ("k".into(), CipherText::Single(leaf(1, 1))),
            ("k".into(), CipherText::Single(leaf(2, 1))),
        ]);
        let mut out = Vec::new();
        assert_eq!(encode_ciphertext(&dup, &mut out), Err(CodecError));
        assert!(out.is_empty());
    }

    #[test]
    fn the_encoder_counts_the_containers_above_a_passthrough() {
        // Mirror of the decoder check in
        // `a_frame_payload_shares_the_depth_budget`: below 60 sequences,
        // the payload has `MAX_DEPTH - 61` levels left.
        let below_60 = |payload: PassthroughFrame| -> Ct {
            let mut ct: Ct = CipherText::Passthrough(payload);
            for _ in 0..60 {
                ct = CipherText::Sequence(vec![ct]);
            }
            ct
        };
        let mut out = Vec::new();
        assert!(encode_ciphertext(&below_60(frame(MAX_DEPTH - 61)), &mut out).is_ok());
        assert!(decode(&out).is_ok());
        let mut out = Vec::new();
        assert_eq!(
            encode_ciphertext(&below_60(frame(MAX_DEPTH - 60)), &mut out),
            Err(CodecError)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn a_hand_built_frame_payload_is_validated_before_it_is_written() {
        // The field is public, so a caller can build a payload that is not
        // one node: empty, two nodes, or truncated. Each would misframe the
        // sibling after it (a sealed leaf read as another kind, with other
        // bytes), so the encoder refuses it instead of writing it.
        let two = vec![tags::NULL, tags::NULL];
        let mut truncated = frame(1).0;
        truncated.pop();
        for payload in [Vec::new(), two, truncated] {
            let ct: Ct = CipherText::Sequence(vec![
                CipherText::Passthrough(PassthroughFrame(payload)),
                CipherText::Single(leaf(9, 40)),
            ]);
            let mut out = Vec::new();
            assert_eq!(
                encode_ciphertext(&ct, &mut out),
                Err(CodecError),
                "a payload that is not one frame must not reach the wire"
            );
            assert!(out.is_empty());
        }
    }

    #[test]
    fn a_frame_payload_shares_the_depth_budget() {
        // The passthrough payload is parsed one level deeper, so the frame
        // nesting behind it shares the ciphertext tree's budget rather than
        // restarting it.
        let mut ok = vec![CT_PASSTHROUGH];
        ok.extend_from_slice(&frame(MAX_DEPTH - 1).0);
        assert!(decode(&ok).is_ok());
        let mut too_deep = vec![CT_PASSTHROUGH];
        too_deep.extend_from_slice(&frame(MAX_DEPTH).0);
        assert!(decode(&too_deep).is_err());
        // And below `n` sequences, the payload has `MAX_DEPTH - n - 1` left.
        let mut bytes = nested_seq(0);
        bytes.clear();
        for _ in 0..60 {
            bytes.push(CT_SEQ);
            bytes.extend_from_slice(&1u32.to_le_bytes());
        }
        let mut ok = bytes.clone();
        ok.push(CT_PASSTHROUGH);
        ok.extend_from_slice(&frame(MAX_DEPTH - 61).0);
        assert!(decode(&ok).is_ok());
        bytes.push(CT_PASSTHROUGH);
        bytes.extend_from_slice(&frame(MAX_DEPTH - 60).0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn a_frame_payload_round_trips_as_its_own_bytes() {
        let payload = frame(2);
        let ct: Ct = CipherText::Map(vec![
            ("id".into(), CipherText::Passthrough(payload.clone())),
            ("email".into(), CipherText::Single(leaf(9, 40))),
        ]);
        let out = encode(&ct);
        let decoded = decode(&out).expect("codec");
        let CipherText::Map(entries) = &decoded else {
            panic!("a map decodes as a map");
        };
        assert!(matches!(&entries[0].1, CipherText::Passthrough(frame) if frame.0 == payload.0));
        assert_eq!(encode(&decoded), out);
    }

    #[test]
    fn a_malformed_frame_payload_is_refused() {
        // A truncated array inside the passthrough.
        assert!(decode(&[CT_PASSTHROUGH, ARRAY, 2, 0, 0, 0, tags::NULL]).is_err());
        // Trailing bytes after the one node the passthrough carries.
        assert!(decode(&[CT_PASSTHROUGH, tags::NULL, tags::NULL]).is_err());
        // A passthrough with nothing behind it.
        assert!(decode(&[CT_PASSTHROUGH]).is_err());
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        for kind in [0x00u8, 0x08, 0x7F, 0xF0, 0xFF] {
            assert!(decode(&[kind, 1, 0, 0, 0, 0xAB]).is_err(), "{kind:#04x}");
        }
    }

    #[test]
    fn a_length_that_does_not_fit_the_prefix_is_refused() {
        assert!(write_len(&mut Vec::new(), usize::MAX).is_err());
        let mut out = Vec::new();
        assert!(write_len(&mut out, u32::MAX as usize).is_ok());
        assert_eq!(out, [0xFF; 4]);
    }

    #[test]
    fn the_error_message_is_fixed() {
        assert_eq!(CodecError.to_string(), "malformed ciphertext transport");
        let boxed: Box<dyn std::error::Error> = Box::new(CodecError);
        assert!(boxed.source().is_none());
    }

    /// Refused, or decoded and written back as the same bytes. `encode`
    /// panics if the encoder refuses a tree the decoder accepted.
    fn refused_or_canonical(bytes: &[u8]) -> bool {
        match decode(bytes) {
            Ok(ct) => encode(&ct) == bytes,
            Err(_) => true,
        }
    }

    #[quickcheck]
    fn accepted_bytes_re_encode_exactly(bytes: Vec<u8>) -> bool {
        refused_or_canonical(&bytes)
    }

    /// Random bytes rarely get past the first kind byte, so start from a
    /// valid encoding of every node kind and overwrite one byte.
    #[quickcheck]
    fn a_corrupted_encoding_is_refused_or_canonical(at: usize, byte: u8) -> bool {
        let mut bytes = encode(&CipherText::Map(vec![
            ("id".into(), CipherText::Passthrough(frame(2))),
            (
                "b".into(),
                CipherText::Sequence(vec![
                    CipherText::Single(leaf(9, 4)),
                    CipherText::EmptySequence(leaf(1, 2)),
                    CipherText::EmptyMap(leaf(2, 3)),
                ]),
            ),
        ]));
        let at = at % bytes.len();
        bytes[at] = byte;
        refused_or_canonical(&bytes)
    }
}
