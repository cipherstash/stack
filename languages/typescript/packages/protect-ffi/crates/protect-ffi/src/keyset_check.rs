//! Refuse a client key whose permutations are not permutations (#1911).
//!
//! A client key is the CBOR of recipher's `ProxyKeySet`: four lists of
//! positions, called permutations. recipher 0.2.3 re-encrypts by following
//! each permutation's cycles, in `Permutation::permute_slice_mut`. With a
//! position listed twice, that loop can run forever. With a position out of
//! range, it panics. Neither `ClientKey::from_bytes` in cipherstash-client
//! nor `ProxyKeySet::from_bytes` in recipher checks the lists, and the loop
//! runs only when the first key is derived, after a ZeroKMS round trip. So
//! one changed character in `CS_CLIENT_KEY` made `newClient` spin at full
//! CPU and never settle.
//!
//! This module checks the lists before cipherstash-client sees the key. It
//! is the same check as `check_permutations` in the `stack-kms` crate
//! (#1850), which the Go SDK uses. It is repeated here because that function
//! is private to `stack-kms`, and `stack-kms` is built against a different
//! cipherstash-client, zerokms and recipher from the ones this crate pins.
//!
//! Every error is a fixed message. None includes a value read from the key.

#[cfg(not(target_arch = "wasm32"))]
use cipherstash_client::zerokms::{ClientKey, KeyProvider, KeyProviderError};
use serde::Deserialize;
#[cfg(not(target_arch = "wasm32"))]
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The fields of recipher's `ProxyKeySet`, read a second time only to check
/// them. Its fields are private to recipher, so this mirrors them, and it
/// accepts the same CBOR.
#[derive(Deserialize)]
struct KeySetShape {
    p1: PermutationShape,
    p2_from: PermutationShape,
    p2_to: PermutationShape,
    p3: PermutationShape,
}

/// One permutation of [`KeySetShape`]. Its entries are key material, so it
/// is wiped when it is dropped. A parse that fails partway is not wiped:
/// serde drops the vector it was building without wiping it. recipher's own
/// parse has the same gap.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct PermutationShape {
    permutation: Vec<u8>,
}

/// The number of bytes in a block. p1, p2_from and p2_to each permute the
/// bytes of one block.
const BLOCK_LEN: usize = 16;

/// What [`check_keyset`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeysetCheck {
    /// The bytes are a keyset, and its four permutations are valid.
    Valid,
    /// The bytes are a keyset, and at least one permutation is not valid.
    InvalidPermutations,
    /// The bytes are not the CBOR of a keyset. `ClientKey::from_bytes`
    /// refuses these too, with an error and without deriving a key.
    NotAKeyset,
}

/// Check the permutations of a keyset's CBOR bytes.
///
/// p1, p2_from and p2_to must each be a permutation of `0..16`. p3 permutes
/// the blocks, and must be a permutation of `0..n` for some `n` from 1 to
/// 64. The check does not branch on any one entry, because the entries are
/// secret.
pub(crate) fn check_keyset(bytes: &[u8]) -> KeysetCheck {
    // serde's own error message can print a value read from the key, so it
    // is dropped here.
    let Ok(shape) = serde_cbor::from_slice::<KeySetShape>(bytes) else {
        return KeysetCheck::NotAKeyset;
    };
    let valid = is_permutation(&shape.p1.permutation, Some(BLOCK_LEN))
        & is_permutation(&shape.p2_from.permutation, Some(BLOCK_LEN))
        & is_permutation(&shape.p2_to.permutation, Some(BLOCK_LEN))
        & is_permutation(&shape.p3.permutation, None);
    if valid {
        KeysetCheck::Valid
    } else {
        KeysetCheck::InvalidPermutations
    }
}

/// Whether `p` is a permutation of `0..p.len()`, with `p.len()` from 1 to
/// 64, and equal to `len` when `len` is given. Only the result depends on
/// the entries; no branch does.
fn is_permutation(p: &[u8], len: Option<usize>) -> bool {
    let n = p.len();
    if n == 0 || n > 64 || len.is_some_and(|len| len != n) {
        return false;
    }
    let mut seen = 0u64;
    let mut out_of_range = false;
    for &x in p {
        out_of_range |= usize::from(x) >= n;
        seen |= 1 << (x & 0x3f);
    }
    let all = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    // Every entry is below n, and the n entries are distinct.
    !out_of_range & (seen == all)
}

/// A [`KeyProvider`] that refuses a client key whose permutations are not
/// valid, before the key reaches cipherstash-client's key derivation.
///
/// It wraps the profile store, `~/.cipherstash/secretkey.json`, on the Neon
/// target. A key passed in `clientOpts.clientKey` is checked earlier, when
/// the options are read.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct CheckedKeyProvider<P> {
    inner: P,
    /// Where the key came from, for the error message. A fixed string.
    source: &'static str,
}

#[cfg(not(target_arch = "wasm32"))]
impl<P> CheckedKeyProvider<P> {
    pub(crate) fn new(inner: P, source: &'static str) -> Self {
        Self { inner, source }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<P: KeyProvider + Sync> KeyProvider for CheckedKeyProvider<P> {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        let key = self.inner.client_key().await?;
        if check_client_key(&key) == KeysetCheck::Valid {
            Ok(key)
        } else {
            Err(KeyProviderError::InvalidKey(format!(
                "the client key in {} is not valid: its permutations are not valid. \
                 The key may have been changed or cut short. Replace it with the \
                 client key you were given",
                self.source
            )))
        }
    }
}

/// Check the keyset of a [`ClientKey`] that cipherstash-client has already
/// parsed. cipherstash-client keeps the keyset private, so this reads it
/// back through `to_hex_v1`, and wipes each copy.
#[cfg(not(target_arch = "wasm32"))]
fn check_client_key(key: &ClientKey) -> KeysetCheck {
    let Ok(hex) = key.to_hex_v1().map(Zeroizing::new) else {
        return KeysetCheck::NotAKeyset;
    };
    let Ok(bytes) = hex::decode(hex.as_bytes()).map(Zeroizing::new) else {
        return KeysetCheck::NotAKeyset;
    };
    check_keyset(&bytes)
}

/// Test keysets, written as CBOR by hand so the tests need no key generator.
#[cfg(test)]
pub(crate) mod fixtures {
    /// The positions `0..n`, in order.
    pub(crate) fn identity(n: u8) -> Vec<u8> {
        (0..n).collect()
    }

    /// A keyset made up for tests: identity permutations, with p3 of the
    /// length recipher generates (33).
    pub(crate) fn valid_keyset() -> Vec<u8> {
        keyset(&identity(16), &identity(16), &identity(16), &identity(33))
    }

    /// The CBOR of a keyset with these four permutations, as recipher's
    /// `ProxyKeySet` serializes it.
    pub(crate) fn keyset(p1: &[u8], p2_from: &[u8], p2_to: &[u8], p3: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, 5, 4);
        for (name, p) in [
            ("p1", p1),
            ("p2_from", p2_from),
            ("p2_to", p2_to),
            ("p3", p3),
        ] {
            text(&mut out, name);
            head(&mut out, 5, 1);
            text(&mut out, "permutation");
            head(&mut out, 4, p.len());
            for &x in p {
                head(&mut out, 0, usize::from(x));
            }
        }
        out
    }

    /// A CBOR item head: major type and a length or value below 256.
    fn head(out: &mut Vec<u8>, major: u8, n: usize) {
        let n = u8::try_from(n).expect("below 256");
        if n < 24 {
            out.push((major << 5) | n);
        } else {
            out.extend_from_slice(&[(major << 5) | 24, n]);
        }
    }

    fn text(out: &mut Vec<u8>, s: &str) {
        head(out, 3, s.len());
        out.extend_from_slice(s.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{identity, keyset, valid_keyset};
    use super::*;

    /// Position 0 listed twice, and position 1 missing. recipher's loop never
    /// ends on this list.
    fn repeated() -> Vec<u8> {
        let mut p = identity(16);
        p[1] = 0;
        p
    }

    #[test]
    fn accepts_a_valid_keyset() {
        assert_eq!(check_keyset(&valid_keyset()), KeysetCheck::Valid);
    }

    #[test]
    fn accepts_a_keyset_that_recipher_reads() {
        // The hand-written CBOR must be what recipher reads, or the other
        // tests check a shape that recipher would refuse anyway.
        let bytes = valid_keyset();
        assert!(
            cipherstash_client::zerokms::ClientKey::from_bytes(uuid::Uuid::nil(), &bytes).is_ok()
        );
        assert_eq!(bytes.len(), 168, "recipher's keysets are 168 bytes");
    }

    #[test]
    fn refuses_a_repeated_position_in_any_permutation() {
        let id16 = identity(16);
        let id33 = identity(33);
        let mut p3 = identity(33);
        p3[1] = 0;
        for (label, bytes) in [
            ("p1", keyset(&repeated(), &id16, &id16, &id33)),
            ("p2_from", keyset(&id16, &repeated(), &id16, &id33)),
            ("p2_to", keyset(&id16, &id16, &repeated(), &id33)),
            ("p3", keyset(&id16, &id16, &id16, &p3)),
        ] {
            assert_eq!(
                check_keyset(&bytes),
                KeysetCheck::InvalidPermutations,
                "{label}"
            );
        }
    }

    #[test]
    fn refuses_a_position_out_of_range() {
        let mut p3 = identity(33);
        p3[0] = 33;
        let bytes = keyset(&identity(16), &identity(16), &identity(16), &p3);
        assert_eq!(check_keyset(&bytes), KeysetCheck::InvalidPermutations);
    }

    #[test]
    fn refuses_a_block_permutation_of_the_wrong_length() {
        let bytes = keyset(&identity(8), &identity(16), &identity(16), &identity(33));
        assert_eq!(check_keyset(&bytes), KeysetCheck::InvalidPermutations);
    }

    #[test]
    fn refuses_an_empty_or_too_long_block_permutation_list() {
        for p3 in [Vec::new(), identity(65)] {
            let bytes = keyset(&identity(16), &identity(16), &identity(16), &p3);
            assert_eq!(check_keyset(&bytes), KeysetCheck::InvalidPermutations);
        }
    }

    #[test]
    fn accepts_a_block_permutation_of_64() {
        let bytes = keyset(&identity(16), &identity(16), &identity(16), &identity(64));
        assert_eq!(check_keyset(&bytes), KeysetCheck::Valid);
    }

    #[test]
    fn reports_bytes_that_are_not_a_keyset() {
        assert_eq!(check_keyset(&[0xaa, 0xbb]), KeysetCheck::NotAKeyset);
        assert_eq!(check_keyset(&[]), KeysetCheck::NotAKeyset);
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod provider {
        use super::*;
        use cipherstash_client::zerokms::StaticKeyProvider;

        fn provider(bytes: &[u8]) -> CheckedKeyProvider<StaticKeyProvider> {
            // cipherstash-client accepts the bad key here: that is the bug.
            let key = ClientKey::from_bytes(uuid::Uuid::nil(), bytes).expect("parses");
            CheckedKeyProvider::new(StaticKeyProvider::new(key), "the test store")
        }

        fn block_on<F: std::future::Future>(f: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime")
                .block_on(f)
        }

        #[test]
        fn passes_a_valid_key_through() {
            assert!(block_on(provider(&valid_keyset()).client_key()).is_ok());
        }

        #[test]
        fn refuses_a_key_with_a_repeated_position_and_names_its_source() {
            let bytes = keyset(&identity(16), &repeated(), &identity(16), &identity(33));
            let err = block_on(provider(&bytes).client_key()).expect_err("refused");
            let msg = err.to_string();
            assert!(matches!(err, KeyProviderError::InvalidKey(_)), "{msg}");
            assert!(msg.contains("the test store"), "{msg}");
            assert!(msg.contains("permutations"), "{msg}");
        }
    }
}
