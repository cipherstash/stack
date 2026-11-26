/// The ciphertext tree [`encrypt`](crate::encrypt) produces and
/// [`decrypt`](crate::decrypt) consumes.
///
/// The shape mirrors the structure of the plaintext that was encrypted: a
/// scalar yields [`Single`](CipherText::Single), while non-empty sequences
/// and maps yield [`Sequence`](CipherText::Sequence) and
/// [`Map`](CipherText::Map). Empty composites use the authenticated marker
/// variants [`EmptySequence`](CipherText::EmptySequence) and
/// [`EmptyMap`](CipherText::EmptyMap), since they contain no element
/// ciphertexts to authenticate the supplied AAD. Nested structures are
/// represented recursively. An absent value (`Option::None`, a host null)
/// is a null leaf, a `Single` like any other scalar: the plain null, or a
/// typed null padded to its type's length (see
/// [`tags::TYPED_NULL`](crate::tags::TYPED_NULL)).
///
/// The two parameters:
///
/// - `Leaf` is the sealed leaf the cipher produces
///   ([`Cipher::Leaf`](crate::Cipher::Leaf)) — e.g. [`LocalCipherText`](crate::LocalCipherText)
///   for a local AES cipher, or an envelope leaf that additionally carries
///   a wrapped data key.
/// - `P` is the passthrough payload. For the sink-based path it is a
///   [`PassthroughFrame`](crate::PassthroughFrame): [`Node`](crate::Node)
///   is this tree with that payload.
///
/// Only the `Leaf` type carries a byte-level format commitment (and should
/// implement `serde` where ciphertexts are persisted). The container itself
/// has no canonical byte representation: hosts project it onto their native
/// structures (a JS object tree, the Go binding's transport codec), with
/// leaves as opaque byte strings.
#[derive(Debug)]
pub enum CipherText<Leaf, P> {
    /// A single sealed value.
    Single(Leaf),
    /// A sequence of ciphertexts produced from a sequence-shaped plaintext.
    Sequence(Vec<CipherText<Leaf, P>>),
    /// An empty sequence, authenticated under domain-separated AAD
    /// ([`Context::for_empty_sequence`](crate::Context::for_empty_sequence))
    /// by a marker leaf.
    EmptySequence(Leaf),
    /// A map of (cleartext key, ciphertext value) pairs produced from a
    /// map-shaped plaintext. Keys are stored in the clear but are bound into
    /// each value's AAD via [`Context::for_map_entry`](crate::Context::for_map_entry),
    /// so they cannot be swapped or renamed undetected (passthrough entries
    /// excepted).
    Map(Vec<(String, CipherText<Leaf, P>)>),
    /// An empty map, authenticated under domain-separated AAD
    /// ([`Context::for_empty_map`](crate::Context::for_empty_map)) by a
    /// marker leaf.
    EmptyMap(Leaf),
    /// A subtree passed through the container **unencrypted and
    /// unauthenticated**. Non-sensitive data only — see
    /// [`Sink::passthrough`](crate::Sink::passthrough).
    Passthrough(P),
}
