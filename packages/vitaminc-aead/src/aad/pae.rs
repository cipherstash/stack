use super::Aad;
use std::borrow::Cow;

/// Encode multiple AAD pieces using PAE (Pre-Authentication Encoding)
/// from the PASETO specification.
///
/// Format: LE64(count) || LE64(len(piece[0])) || piece[0] || ...
///
/// This ensures unambiguous encoding: different inputs always produce
/// different byte sequences.
pub(crate) fn encode(pieces: &[&[u8]]) -> Aad<'static> {
    let total_len = 8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        buf.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        buf.extend_from_slice(piece);
    }
    // The pre-computed `total_len` is only a capacity hint, so a wrong value
    // wouldn't change the output. Assert it matches the bytes we actually wrote,
    // both as a defensive invariant and so the formula stays covered by tests.
    debug_assert_eq!(
        buf.len(),
        total_len,
        "PAE capacity hint must equal the encoded length"
    );
    Aad(Cow::Owned(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    // ---------------------------------------------------------------
    // Unit tests: encoding format
    // ---------------------------------------------------------------

    #[test]
    fn empty_pieces() {
        let aad = encode(&[]);
        // LE64(0) = 8 zero bytes
        assert_eq!(aad.as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn single_empty_piece() {
        let aad = encode(&[b""]);
        // LE64(1) || LE64(0) = 16 bytes
        let mut expected = vec![];
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(aad.as_bytes(), &expected);
    }

    #[test]
    fn single_piece() {
        let aad = encode(&[b"test"]);
        // LE64(1) || LE64(4) || b"test"
        let mut expected = vec![];
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(b"test");
        assert_eq!(aad.as_bytes(), &expected);
    }

    #[test]
    fn two_pieces() {
        let aad = encode(&[b"foo", b"bar"]);
        let mut expected = vec![];
        expected.extend_from_slice(&2u64.to_le_bytes()); // count
        expected.extend_from_slice(&3u64.to_le_bytes()); // len("foo")
        expected.extend_from_slice(b"foo");
        expected.extend_from_slice(&3u64.to_le_bytes()); // len("bar")
        expected.extend_from_slice(b"bar");
        assert_eq!(aad.as_bytes(), &expected);
    }

    // ---------------------------------------------------------------
    // Unit tests: targeted attack scenarios
    // ---------------------------------------------------------------

    #[test]
    fn different_splits_produce_different_encodings() {
        // Attacker shifts a byte from piece 1 to piece 0
        let aad1 = encode(&[b"ab", b"cd"]);
        let aad2 = encode(&[b"a", b"bcd"]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }

    #[test]
    fn trailing_empty_piece_differs_from_no_trailing() {
        // Attacker appends an empty piece hoping it's invisible
        let aad1 = encode(&[b"foo", b"bar"]);
        let aad2 = encode(&[b"foo", b"bar", b""]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }

    #[test]
    fn leading_empty_piece_differs() {
        // Attacker prepends an empty piece
        let aad1 = encode(&[b"foo"]);
        let aad2 = encode(&[b"", b"foo"]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }

    #[test]
    fn single_vs_split_produces_different_encodings() {
        // Attacker tries to pass concatenated content as a single piece
        let aad1 = encode(&[b"foobar"]);
        let aad2 = encode(&[b"foo", b"bar"]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }

    #[test]
    fn embedded_fake_length_prefix_does_not_collide() {
        // Attacker embeds LE64(3) inside piece data to mimic the framing
        // of a two-piece encoding
        let fake_framing = {
            let mut v = Vec::new();
            v.extend_from_slice(&3u64.to_le_bytes()); // fake length prefix
            v.extend_from_slice(b"bar");
            v
        };
        let aad1 = encode(&[b"foo", b"bar"]);
        let aad2 = encode(&[&fake_framing]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }

    #[test]
    fn all_empty_pieces_differ_by_count() {
        let aad1 = encode(&[b"", b""]);
        let aad2 = encode(&[b"", b"", b""]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }

    // ---------------------------------------------------------------
    // Property tests
    // ---------------------------------------------------------------

    #[quickcheck]
    fn deterministic(pieces: Vec<Vec<u8>>) -> bool {
        let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
        encode(&refs).as_bytes() == encode(&refs).as_bytes()
    }

    #[quickcheck]
    fn output_length_matches_formula(pieces: Vec<Vec<u8>>) -> bool {
        let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
        let expected_len = 8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>();
        encode(&refs).as_bytes().len() == expected_len
    }

    #[quickcheck]
    fn shifting_boundary_is_injective(a: Vec<u8>, b: Vec<u8>) -> bool {
        // For any non-empty `a`, moving the last byte from `a` to `b`
        // must produce a different encoding.
        if a.is_empty() {
            return true;
        }
        let split = a.len() - 1;
        let a1 = &a[..split];
        let mut b1 = vec![a[split]];
        b1.extend_from_slice(&b);

        encode(&[&a, &b]).as_bytes() != encode(&[a1, &b1]).as_bytes()
    }

    #[quickcheck]
    fn different_piece_count_is_injective(a: Vec<u8>, b: Vec<u8>) -> bool {
        // [a || b] as one piece must differ from [a, b] as two pieces
        let mut combined = a.clone();
        combined.extend_from_slice(&b);
        encode(&[&combined]).as_bytes() != encode(&[&a, &b]).as_bytes()
    }

    #[quickcheck]
    fn appending_empty_piece_changes_encoding(pieces: Vec<Vec<u8>>) -> bool {
        let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
        let mut with_extra = refs.clone();
        with_extra.push(b"");
        encode(&refs).as_bytes() != encode(&with_extra).as_bytes()
    }
}
