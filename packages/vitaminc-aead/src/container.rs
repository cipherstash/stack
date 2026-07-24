/// The recursive ciphertext container shared by tree-shaped [`Cipher`]
/// implementations.
///
/// The shape mirrors the structure of the plaintext that was encrypted: a
/// single value yields [`Single`](CipherText::Single), while non-empty `Vec`s
/// and `HashMap`s yield [`Sequence`](CipherText::Sequence) and
/// [`Map`](CipherText::Map). Empty composites use the authenticated marker
/// variants [`EmptySequence`](CipherText::EmptySequence) and
/// [`EmptyMap`](CipherText::EmptyMap), since they contain no element
/// ciphertexts to authenticate the supplied AAD. Nested structures are
/// represented recursively.
///
/// Concrete ciphers instantiate the two parameters:
///
/// - `Leaf` is the sealed leaf ciphertext (nonce + ciphertext + tag) — e.g.
///   [`LocalCipherText`](crate::LocalCipherText) for a local AES cipher, or an
///   envelope leaf that additionally carries a wrapped data key.
/// - `P` is the passthrough payload type, fixed by the cipher's
///   [`Cipher::Passthrough`](crate::Cipher::Passthrough) associated type.
///   Rust-native ciphers typically use `Box<dyn Any + Send>`; FFI-targeting
///   ciphers use an owned host-value type carried value-in/value-out.
///
/// Only the `Leaf` type carries a byte-level format commitment (and should
/// implement `serde` where ciphertexts are persisted). The container itself
/// has no canonical byte representation: hosts project it onto their native
/// structures (e.g. a JS object tree across an FFI boundary), with leaves as
/// opaque byte strings.
///
/// [`Cipher`]: crate::Cipher
#[derive(Debug)]
pub enum CipherText<Leaf, P> {
    /// A single sealed value.
    Single(Leaf),
    /// A sequence of ciphertexts produced from a `Vec`-shaped plaintext.
    Sequence(Vec<CipherText<Leaf, P>>),
    /// An empty sequence, authenticated under domain-separated AAD via the
    /// marker leaf produced at [`SeqCipher::end`](crate::SeqCipher::end).
    EmptySequence(Leaf),
    /// A map of (cleartext key, ciphertext value) pairs produced from a
    /// map-shaped plaintext. Keys are stored in the clear but are bound into
    /// each value's AAD via [`Aad::for_map_entry`](crate::Aad::for_map_entry),
    /// so they cannot be swapped or renamed undetected (passthrough entries
    /// excepted).
    Map(Vec<(String, CipherText<Leaf, P>)>),
    /// An empty map, authenticated under domain-separated AAD via the marker
    /// leaf produced at [`MapCipher::end`](crate::MapCipher::end).
    EmptyMap(Leaf),
    /// The authenticated absent marker produced by
    /// [`Cipher::encrypt_none`](crate::Cipher::encrypt_none). Stores a sealed
    /// empty plaintext whose tag binds the supplied AAD.
    None(Leaf),
    /// A value passed through the container **unencrypted and
    /// unauthenticated** via [`Cipher::passthrough`](crate::Cipher::passthrough).
    /// Non-sensitive data only — see the trait docs.
    Passthrough(P),
}

impl<Leaf, P> CipherText<Leaf, P> {
    /// Recursively convert the passthrough payload type, leaving the sealed
    /// structure untouched.
    ///
    /// This is the bridge between ciphers with different passthrough
    /// currencies — e.g. re-homing a tree between the Rust-native
    /// `Box<dyn Any + Send>` currency and an owned FFI value type at an FFI
    /// boundary. The conversion is fallible so payloads that cannot be
    /// represented in the target currency surface an error instead of being
    /// silently dropped; a tree containing no passthrough values never
    /// invokes `f`.
    pub fn map_passthrough<Q, E, F>(self, f: &mut F) -> Result<CipherText<Leaf, Q>, E>
    where
        F: FnMut(P) -> Result<Q, E>,
    {
        Ok(match self {
            CipherText::Single(leaf) => CipherText::Single(leaf),
            CipherText::None(leaf) => CipherText::None(leaf),
            CipherText::EmptySequence(leaf) => CipherText::EmptySequence(leaf),
            CipherText::EmptyMap(leaf) => CipherText::EmptyMap(leaf),
            CipherText::Sequence(items) => CipherText::Sequence(
                items
                    .into_iter()
                    .map(|item| item.map_passthrough(f))
                    .collect::<Result<_, E>>()?,
            ),
            CipherText::Map(entries) => CipherText::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| value.map_passthrough(f).map(|value| (key, value)))
                    .collect::<Result<_, E>>()?,
            ),
            CipherText::Passthrough(value) => CipherText::Passthrough(f(value)?),
        })
    }
}
