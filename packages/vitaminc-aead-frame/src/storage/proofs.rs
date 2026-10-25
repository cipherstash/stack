//! Kani proof harnesses for the storage reader, which parses bytes that may
//! be corrupt or tampered with. The tests and the fuzzing show that it
//! refuses bad input without panicking, for the inputs they try. These
//! show it for every input within the stated bounds.
//!
//! A harness over whole bodies (`validate` on any few bytes) was tried and
//! did not solve in twenty minutes, even for three bytes. Each level of
//! nesting copies the whole reader once per kind of container, and the
//! object's hash set and the leaf codec with it. A function contract on
//! `node`, which avoids the copies, did not solve for four bytes either. So
//! the pieces a body is read with are proved here: the header, a count, a
//! scalar, an object's key, a map's key, the depth bound and a map key's
//! identity. The property tests and the fuzzing cover whole bodies.
//!
//! Run with `cargo kani -p vitaminc-aead-frame --features serde`.

use vitaminc_aead::tags;

use super::{body, node, Cursor, ErrorKind, Invalid, MapKey, MAGIC, MAX_DEPTH, VERSION};

/// Any `N` bytes, and a length up to `N`: every input of at most `N` bytes.
fn any_bytes<const N: usize>() -> ([u8; N], usize) {
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    (bytes, len)
}

/// Rules 1 and 2 of *Reading*, and nothing else: a blob is refused as not
/// a blob when it is shorter than four bytes or does not start with
/// `"VCS"`, refused as an unsupported version when its version is not 1,
/// and otherwise its body is everything after the header.
#[kani::proof]
#[kani::unwind(8)]
fn the_header_is_refused_exactly_as_its_rules_say() {
    let (bytes, len) = any_bytes::<6>();
    let input = &bytes[..len];
    let magic = len >= 3 && bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2];
    match body(input) {
        Ok(rest) => {
            assert!(len >= 4 && magic && bytes[3] == VERSION);
            // The rest of the input itself, not a copy.
            assert!(core::ptr::eq(rest, &input[4..]));
        }
        Err(e) if e.kind() == ErrorKind::NotABlob => assert!(len < 4 || !magic),
        Err(e) => {
            assert!(e.kind() == ErrorKind::UnsupportedVersion);
            assert!(len >= 4 && magic && bytes[3] != VERSION);
        }
    }
}

/// A count is read from four bytes, and refused exactly when they are not
/// there or it is more than the bytes left after them, so no loop over a
/// count runs past the end of the blob.
#[kani::proof]
fn a_count_is_never_more_than_the_bytes_left() {
    let (bytes, len) = any_bytes::<8>();
    let pos: usize = kani::any();
    kani::assume(pos <= len);
    let mut cursor = Cursor {
        buf: &bytes[..len],
        pos,
    };
    let left = len - pos;
    let expected = (left >= 4)
        .then(|| u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]))
        .filter(|&n| n as usize <= left - 4);
    match cursor.count() {
        Ok(n) => {
            assert!(expected == Some(n as u32));
            assert!(cursor.pos == pos + 4);
            assert!(n <= len - cursor.pos);
        }
        Err(_) => assert!(expected.is_none()),
    }
}

/// The bound on the input the cursor harnesses below check.
const INPUT: usize = 6;

/// A cursor over any input of at most [`INPUT`] bytes, at any position in
/// it.
fn any_cursor(bytes: &[u8; INPUT]) -> Cursor<'_> {
    let len: usize = kani::any();
    kani::assume(len <= INPUT);
    let pos: usize = kani::any();
    kani::assume(pos <= len);
    Cursor {
        buf: &bytes[..len],
        pos,
    }
}

/// Whether `part` lies within `whole`, where the cursor read it from.
fn within(part: &[u8], whole: &[u8]) -> bool {
    let (start, end) = (
        whole.as_ptr() as usize,
        whole.as_ptr() as usize + whole.len(),
    );
    part.as_ptr() as usize >= start && part.as_ptr() as usize + part.len() <= end
}

/// Reading a scalar never panics, and what it reads, and where it leaves
/// the cursor, lie within the input.
#[kani::proof]
#[kani::unwind(8)]
fn reading_a_scalar_stays_in_bounds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    match cursor.scalar() {
        Ok(scalar) => {
            assert!(within(scalar, buf));
            assert!(cursor.pos == pos + scalar.len());
            assert!(cursor.pos <= buf.len());
        }
        Err(_) => assert!(cursor.pos == pos),
    }
}

/// Reading an object's key never panics, gives UTF-8 from within the
/// input, and leaves the cursor within it.
#[kani::proof]
#[kani::unwind(8)]
fn reading_an_object_key_stays_in_bounds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let buf = cursor.buf;
    if let Ok(key) = cursor.key() {
        assert!(within(key.as_bytes(), buf));
        assert!(cursor.pos <= buf.len());
    }
}

/// Reading a map's key never panics, and accepts only an integer, text or
/// bytes scalar from within the input.
#[kani::proof]
#[kani::unwind(14)]
fn reading_a_map_key_admits_only_its_kinds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    if let Ok(MapKey(key)) = cursor.map_key() {
        assert!(within(key, buf));
        assert!(super::KEYS.contains(&buf[pos]));
        assert!(cursor.pos <= buf.len());
    }
}

/// A node past the depth bound is refused before a byte of it is read, so
/// no call checks a node deeper than 128, and recursion stops there. The
/// check is one comparison, proved at the depths just past the bound and at
/// the largest: a symbolic depth keeps the whole reader in the formula, and
/// did not solve in fifteen minutes.
#[kani::proof]
#[kani::unwind(4)]
fn a_node_past_the_depth_bound_is_refused_unread() {
    let (bytes, len) = any_bytes::<4>();
    for depth in [MAX_DEPTH + 1, MAX_DEPTH + 2, usize::MAX] {
        let mut cursor = Cursor {
            buf: &bytes[..len],
            pos: 0,
        };
        assert!(node(&mut cursor, depth) == Err(Invalid::Malformed));
        assert!(cursor.pos == 0);
    }
}

/// The integer tags, and the width of each one's payload.
const INTEGERS: [(u8, usize); 10] = [
    (tags::INT8, 1),
    (tags::INT16, 2),
    (tags::INT32, 4),
    (tags::INT64, 8),
    (tags::INT128, 16),
    (tags::UINT8, 1),
    (tags::UINT16, 2),
    (tags::UINT32, 4),
    (tags::UINT64, 8),
    (tags::UINT128, 16),
];

/// An integer key of the width `tag` names, holding any value: its node,
/// and the node's length. The tag is concrete, so the leaf codec's paths
/// for every other tag are pruned rather than solved.
fn any_integer_key((tag, width): (u8, usize)) -> ([u8; 17], usize) {
    let payload: [u8; 16] = kani::any();
    let mut node = [0; 17];
    node[0] = tag;
    node[1..=width].copy_from_slice(&payload[..width]);
    (node, 1 + width)
}

/// An integer's value, worked out from its node without the leaf codec:
/// as an `i128`, or for a `u128` above `i128::MAX`, as that.
#[derive(PartialEq, Eq)]
enum Value {
    Signed(i128),
    Huge(u128),
}

fn value(node: &[u8]) -> Value {
    let payload = &node[1..];
    let mut word = [0; 16];
    word[..payload.len()].copy_from_slice(payload);
    let unsigned = u128::from_le_bytes(word);
    let signed = |bits: u32| (unsigned << (128 - bits)) as i128 >> (128 - bits);
    Value::Signed(match node[0] {
        tags::INT8 => signed(8),
        tags::INT16 => signed(16),
        tags::INT32 => signed(32),
        tags::INT64 => signed(64),
        tags::INT128 => unsigned as i128,
        _ => match i128::try_from(unsigned) {
            Ok(v) => v,
            Err(_) => return Value::Huge(unsigned),
        },
    })
}

/// Two integer keys are one key exactly when their values are equal,
/// whatever their widths and signedness, so a map refuses `1u8` beside
/// `1u64`, and keeps `-1i8` beside `255u8`.
#[kani::proof]
#[kani::unwind(18)]
fn integer_keys_are_one_key_exactly_when_their_values_are_equal() {
    // Equality is symmetric, so each unordered pair of widths is enough.
    for (i, first) in INTEGERS.into_iter().enumerate() {
        for second in INTEGERS.into_iter().skip(i) {
            let (a, a_len) = any_integer_key(first);
            let (b, b_len) = any_integer_key(second);
            let (a, b) = (&a[..a_len], &b[..b_len]);
            let same = MapKey(a).identity() == MapKey(b).identity();
            assert!(same == (value(a) == value(b)));
        }
    }
}

/// Text and bytes keys are never one key with each other, or with an
/// integer, even when their bytes are the same. Each length is taken in
/// turn, as a symbolic one would have UTF-8 validation solved over every
/// length at once.
#[kani::proof]
#[kani::unwind(18)]
fn keys_of_different_kinds_are_never_one_key() {
    let payload: [u8; 2] = kani::any();
    for len in 0..=payload.len() {
        let counted = |tag: u8| {
            let mut node = [0; 7];
            node[0] = tag;
            node[1] = len as u8;
            node[5..5 + len].copy_from_slice(&payload[..len]);
            (node, 5 + len)
        };
        let (text, text_len) = counted(tags::STRING);
        let (bytes, bytes_len) = counted(tags::BYTES);
        let text = MapKey(&text[..text_len]).identity();
        let bytes = MapKey(&bytes[..bytes_len]).identity();
        assert!(text != bytes);
        for width in INTEGERS {
            let (int, int_len) = any_integer_key(width);
            let int = MapKey(&int[..int_len]).identity();
            assert!(text != int);
            assert!(bytes != int);
        }
    }
}
