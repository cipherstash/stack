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

use super::{
    body, node, Cursor, ErrorKind, Invalid, MapKey, ARRAY, HEADER, MAGIC, MAP, MAX_DEPTH, SOME,
    VERSION,
};

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
    let whole = len >= HEADER.len();
    match body(input) {
        Ok(rest) => {
            assert!(whole && magic && bytes[3] == VERSION);
            // The rest of the input itself, not a copy.
            assert!(core::ptr::eq(rest, &input[HEADER.len()..]));
        }
        Err(e) if e.kind() == ErrorKind::NotABlob => assert!(!whole || !magic),
        Err(e) => {
            assert!(e.kind() == ErrorKind::UnsupportedVersion);
            assert!(whole && magic && bytes[3] != VERSION);
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

/// A null or a `u8` at the cursor, whole: a scalar the reader must accept,
/// and how many bytes it takes. So a reader that refused everything would
/// fail the harnesses below, which also show what it accepts is in bounds.
fn plainly_valid(buf: &[u8], pos: usize) -> Option<usize> {
    match buf.get(pos) {
        Some(&tags::NULL) => Some(1),
        Some(&tags::UINT8) if buf.len() - pos >= 2 => Some(2),
        _ => None,
    }
}

/// Reading a scalar never panics. It reads the bytes at the cursor and
/// moves past them, at least one, or refuses and leaves the cursor where
/// it was; it accepts a plainly valid one.
#[kani::proof]
#[kani::unwind(8)]
fn reading_a_scalar_stays_in_bounds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    let valid = plainly_valid(buf, pos);
    match cursor.scalar() {
        Ok(scalar) => {
            assert!(cursor.pos > pos);
            assert!(core::ptr::eq(scalar, &buf[pos..cursor.pos]));
            assert!(valid.is_none_or(|n| scalar.len() == n));
        }
        Err(_) => {
            assert!(valid.is_none());
            assert!(cursor.pos == pos);
        }
    }
}

/// Reading an object's key never panics, and is read exactly when the
/// cursor holds a `u32` length that the bytes left hold, then that many
/// bytes of UTF-8: those bytes are the key.
#[kani::proof]
#[kani::unwind(8)]
fn reading_an_object_key_stays_in_bounds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    let left = buf.len() - pos;
    let expected = (left >= 4)
        .then(|| u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize)
        .filter(|&n| n <= left - 4)
        .filter(|&n| utf8(&buf[pos + 4..pos + 4 + n]));
    match cursor.key() {
        Ok(key) => {
            assert!(expected == Some(key.len()));
            assert!(core::ptr::eq(key.as_bytes(), &buf[pos + 4..cursor.pos]));
        }
        Err(_) => assert!(expected.is_none()),
    }
}

/// The harness above reads a key of at most two bytes, too few for a
/// three- or four-byte UTF-8 sequence. So a key of four bytes, any four, is
/// read here: it is read exactly when they are UTF-8.
#[kani::proof]
#[kani::unwind(8)]
fn a_four_byte_object_key_is_read_exactly_when_it_is_utf8() {
    let text: [u8; 4] = kani::any();
    let mut buf = [4, 0, 0, 0, 0, 0, 0, 0];
    buf[4..].copy_from_slice(&text);
    let mut cursor = Cursor { buf: &buf, pos: 0 };
    assert!(cursor.key().is_ok() == utf8(&text));
}

/// Whether `bytes` are UTF-8, by RFC 3629's table, written apart from the
/// standard library's check that the reader uses.
fn utf8(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // The sequence's length, and the range its second byte must be in.
        let (n, low, high) = match b {
            0x00..=0x7F => (1, 0, 0),
            0xC2..=0xDF => (2, 0x80, 0xBF),
            0xE0 => (3, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (3, 0x80, 0xBF),
            0xED => (3, 0x80, 0x9F),
            0xF0 => (4, 0x90, 0xBF),
            0xF1..=0xF3 => (4, 0x80, 0xBF),
            0xF4 => (4, 0x80, 0x8F),
            _ => return false,
        };
        if i + n > bytes.len() {
            return false;
        }
        if n > 1 && !(low..=high).contains(&bytes[i + 1]) {
            return false;
        }
        if bytes[i + 2.min(n)..i + n]
            .iter()
            .any(|&c| !(0x80..=0xBF).contains(&c))
        {
            return false;
        }
        i += n;
    }
    true
}

/// The tags STORAGE.md's grammar lets a map's key start with (`key =
/// integer / text / bytes`), written out from its scalar table rather than
/// taken from the reader's own list.
fn a_key_tag(tag: u8) -> bool {
    matches!(
        tag,
        0x0C | 0x0E | 0x04 | 0x05 | 0x10 | 0x0D | 0x0F | 0x06 | 0x07 | 0x11 | 0x0A | 0x0B
    )
}

/// Reading a map's key never panics, and accepts only an integer, text or
/// bytes scalar, at the cursor; it accepts a whole `u8` key.
#[kani::proof]
#[kani::unwind(14)]
fn reading_a_map_key_admits_only_its_kinds() {
    let bytes: [u8; INPUT] = kani::any();
    let mut cursor = any_cursor(&bytes);
    let (buf, pos) = (cursor.buf, cursor.pos);
    let a_u8 = buf.get(pos) == Some(&tags::UINT8) && buf.len() - pos >= 2;
    match cursor.map_key() {
        Ok(MapKey(key)) => {
            assert!(cursor.pos > pos);
            assert!(core::ptr::eq(key, &buf[pos..cursor.pos]));
            assert!(a_key_tag(buf[pos]));
        }
        Err(_) => assert!(!a_u8),
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
            // An integer is a key; a float never is.
            let mut cursor = Cursor { buf, pos: 0 };
            assert!(cursor.map_key().is_ok() == (whole && tag != tags::FLOAT64));
        }
    }
}

/// A node past the depth bound is refused before a byte of it is read, so
/// no call checks a node deeper than 128, and recursion stops there; a
/// node at 128 is still read. The check is one comparison,
/// proved at the depths on either side of the bound and at the largest: a
/// symbolic depth keeps the whole reader in the formula, and did not solve
/// in fifteen minutes.
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
    assert!(MAX_DEPTH == 128);
    // A null at 128 reads.
    assert!(
        node(
            &mut Cursor {
                buf: &[tags::NULL],
                pos: 0
            },
            MAX_DEPTH
        ) == Ok(())
    );
}

/// A container holding a null reads at 127, and is refused at 128, since
/// what it holds is at 129: each container passes its children down a
/// level, so recursion stops at the bound. One harness for each, as one
/// harness over them all did not solve in ten minutes.
fn passes_children_down_a_level(container: &[u8]) {
    let at = |depth| {
        node(
            &mut Cursor {
                buf: container,
                pos: 0,
            },
            depth,
        )
    };
    assert!(at(MAX_DEPTH - 1) == Ok(()));
    assert!(at(MAX_DEPTH) == Err(Invalid::Malformed));
}

#[kani::proof]
#[kani::unwind(4)]
fn a_some_passes_its_value_down_a_level() {
    passes_children_down_a_level(&[SOME, tags::NULL]);
}

#[kani::proof]
#[kani::unwind(4)]
fn an_array_passes_its_elements_down_a_level() {
    passes_children_down_a_level(&[ARRAY, 1, 0, 0, 0, tags::NULL]);
}

/// A map at 128 holding a null is refused, so it passes its values down a
/// level. That it reads at 127 is left to the corpus's `depth_128_maps`
/// row: once its value reads, a map checks its keys for a repeat, and that
/// did not solve in ten minutes.
#[kani::proof]
// The key's tag is looked up in a list of twelve.
#[kani::unwind(14)]
fn a_map_passes_its_values_down_a_level() {
    let map = [MAP, 1, 0, 0, 0, tags::UINT8, 1, tags::NULL];
    let mut cursor = Cursor { buf: &map, pos: 0 };
    assert!(node(&mut cursor, MAX_DEPTH) == Err(Invalid::Malformed));
}

// An object is not proved here: it finds a repeated key with a `HashSet`,
// whose hasher asks the OS for random bytes, which Kani cannot model. The
// corpus's `depth_128_objects` and `depth_129_objects` rows pin its depth.

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
