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

/// Reading a scalar never panics. It reads the bytes at the cursor and
/// moves past them, at least one, or refuses and leaves the cursor where
/// it was.
#[kani::proof]
#[kani::unwind(8)]
fn reading_a_scalar_stays_in_bounds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    match cursor.scalar() {
        Ok(scalar) => {
            assert!(cursor.pos > pos);
            assert!(core::ptr::eq(scalar, &buf[pos..cursor.pos]));
        }
        Err(_) => assert!(cursor.pos == pos),
    }
}

/// Reading an object's key never panics, and gives the UTF-8 after the
/// key's length, at the cursor.
#[kani::proof]
#[kani::unwind(8)]
fn reading_an_object_key_stays_in_bounds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    if let Ok(key) = cursor.key() {
        assert!(core::ptr::eq(key.as_bytes(), &buf[pos + 4..cursor.pos]));
    }
}

/// Reading a map's key never panics, and accepts only an integer, text or
/// bytes scalar, at the cursor.
#[kani::proof]
#[kani::unwind(14)]
fn reading_a_map_key_admits_only_its_kinds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    if let Ok(MapKey(key)) = cursor.map_key() {
        assert!(cursor.pos > pos);
        assert!(core::ptr::eq(key, &buf[pos..cursor.pos]));
        assert!(super::KEYS.contains(&buf[pos]));
    }
}

/// The harnesses above read at most [`INPUT`] bytes, too few for an 8- or
/// 16-byte payload. So each wide scalar is read here, from the start of
/// every length of input up to 17 bytes: it is all of its width when the
/// input holds it, and is refused otherwise. The integers are read as map
/// keys too. Tags and lengths are taken in turn and only the payload is
/// symbolic, as a symbolic length did not solve in twenty minutes.
#[kani::proof]
#[kani::unwind(19)]
fn reading_a_wide_scalar_takes_exactly_its_width() {
    let mut bytes: [u8; 17] = kani::any();
    for (tag, width) in [
        (tags::INT64, 8),
        (tags::UINT64, 8),
        (tags::FLOAT64, 8),
        (tags::INT128, 16),
        (tags::UINT128, 16),
    ] {
        bytes[0] = tag;
        for len in 0..=bytes.len() {
            let buf = &bytes[..len];
            let whole = len > width;
            let mut cursor = Cursor { buf, pos: 0 };
            match cursor.scalar() {
                Ok(scalar) => assert!(whole && core::ptr::eq(scalar, &buf[..1 + width])),
                Err(_) => assert!(!whole && cursor.pos == 0),
            }
            if tag != tags::FLOAT64 {
                let mut cursor = Cursor { buf, pos: 0 };
                assert!(cursor.map_key().is_ok() == whole);
            }
        }
    }
}

/// A node past the depth bound is refused before a byte of it is read, so
/// no call checks a node deeper than 128, and recursion stops there; a
/// node at 128 is still read. The check is one comparison, proved at the
/// depths on either side of the bound and at the largest: a symbolic
/// depth keeps the whole reader in the formula, and did not solve in
/// fifteen minutes.
#[kani::proof]
#[kani::unwind(4)]
fn the_depth_bound_is_128() {
    let (bytes, len) = any_bytes::<4>();
    for depth in [MAX_DEPTH + 1, MAX_DEPTH + 2, usize::MAX] {
        let mut cursor = Cursor {
            buf: &bytes[..len],
            pos: 0,
        };
        assert!(node(&mut cursor, depth) == Err(Invalid::Malformed));
        assert!(cursor.pos == 0);
    }
    // A null at 128 reads, and so does one inside a `some` at 127; a
    // `some` at 128 is refused, since what it holds is at 129.
    let null = [tags::NULL];
    let some_null = [super::SOME, tags::NULL];
    let at = |buf: &[u8], depth| node(&mut Cursor { buf, pos: 0 }, depth);
    assert!(at(&null, MAX_DEPTH) == Ok(()));
    assert!(at(&some_null, MAX_DEPTH - 1) == Ok(()));
    assert!(at(&some_null, MAX_DEPTH) == Err(Invalid::Malformed));
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
/// `1u64`, and keeps `-1i8` beside `255u8`. Checked for the key of width
/// `INTEGERS[first]` against every width from it on: equality is
/// symmetric, so the harnesses below check each unordered pair once, one
/// harness per first width so they run in parallel.
fn integer_keys_from(first: usize) {
    let (a, a_len) = any_integer_key(INTEGERS[first]);
    let a = &a[..a_len];
    for second in INTEGERS.into_iter().skip(first) {
        let (b, b_len) = any_integer_key(second);
        let b = &b[..b_len];
        let same = MapKey(a).identity() == MapKey(b).identity();
        assert!(same == (value(a) == value(b)));
    }
}

macro_rules! integer_key_harnesses {
    ($($name:ident = $first:expr;)*) => {$(
        #[kani::proof]
        #[kani::unwind(18)]
        fn $name() {
            integer_keys_from($first);
        }
    )*};
}

integer_key_harnesses! {
    integer_keys_equal_by_value_from_i8 = 0;
    integer_keys_equal_by_value_from_i16 = 1;
    integer_keys_equal_by_value_from_i32 = 2;
    integer_keys_equal_by_value_from_i64 = 3;
    integer_keys_equal_by_value_from_i128 = 4;
    integer_keys_equal_by_value_from_u8 = 5;
    integer_keys_equal_by_value_from_u16 = 6;
    integer_keys_equal_by_value_from_u32 = 7;
    integer_keys_equal_by_value_from_u64 = 8;
    integer_keys_equal_by_value_from_u128 = 9;
}

/// A text or bytes key of `len` bytes, any bytes: its node, and the node's
/// length.
fn counted(tag: u8, payload: &[u8; 2], len: usize) -> ([u8; 7], usize) {
    let mut node = [0; 7];
    node[0] = tag;
    node[1] = len as u8;
    node[5..5 + len].copy_from_slice(&payload[..len]);
    (node, 5 + len)
}

/// Two text keys, or two bytes keys, are one key exactly when their bytes
/// are equal. Each pair of lengths up to two is taken in turn, as a
/// symbolic length would have UTF-8 validation solved over every length at
/// once.
#[kani::proof]
#[kani::unwind(8)]
fn text_and_bytes_keys_equal_by_their_bytes() {
    let (p, q): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    for tag in [tags::STRING, tags::BYTES] {
        for m in 0..=2 {
            for n in 0..=2 {
                let (a, a_len) = counted(tag, &p, m);
                let (b, b_len) = counted(tag, &q, n);
                let same = MapKey(&a[..a_len]).identity() == MapKey(&b[..b_len]).identity();
                assert!(same == (p[..m] == q[..n]));
            }
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
    let ints = INTEGERS.map(any_integer_key);
    let ints = ints
        .each_ref()
        .map(|(node, len)| MapKey(&node[..*len]).identity());
    let payload: [u8; 2] = kani::any();
    for len in 0..=payload.len() {
        let (text, text_len) = counted(tags::STRING, &payload, len);
        let (bytes, bytes_len) = counted(tags::BYTES, &payload, len);
        let text = MapKey(&text[..text_len]).identity();
        let bytes = MapKey(&bytes[..bytes_len]).identity();
        assert!(text != bytes);
        for int in &ints {
            assert!(text != *int);
            assert!(bytes != *int);
        }
    }
}
