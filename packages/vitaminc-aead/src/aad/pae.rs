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
    Aad(Cow::Owned(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn different_splits_produce_different_encodings() {
        // "ab" + "cd" vs "a" + "bcd"
        let aad1 = encode(&[b"ab", b"cd"]);
        let aad2 = encode(&[b"a", b"bcd"]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());

        // "foobar" + "" vs "foo" + "bar"
        let aad3 = encode(&[b"foobar", b""]);
        let aad4 = encode(&[b"foo", b"bar"]);
        assert_ne!(aad3.as_bytes(), aad4.as_bytes());
    }

    #[test]
    fn different_piece_counts_produce_different_encodings() {
        // 1 piece ["ab"] vs 2 pieces ["a", "b"]
        let aad1 = encode(&[b"ab"]);
        let aad2 = encode(&[b"a", b"b"]);
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());
    }
}
