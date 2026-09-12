mod pae;
mod piece;

use std::borrow::Cow;

pub use piece::AadPiece;

use vitaminc_protected::NonEmpty;

/// Associated Authenticated Data passed to an AEAD cipher.
///
/// `Aad` is authenticated but not encrypted: tampering with it (or with the
/// associated ciphertext) causes decryption to fail. The underlying storage is
/// copy-on-write so borrowed slices can be passed without an allocation.
#[derive(Clone)]
pub struct Aad<'a>(Cow<'a, [u8]>);

impl<'a> Aad<'a> {
    /// Returns an empty `Aad` — no associated data is authenticated.
    pub fn empty() -> Self {
        Aad(Cow::Borrowed(&[]))
    }

    /// Constructs an owned `Aad` by collecting the iterator into a `Vec<u8>`.
    pub fn new_owned<I>(aad: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        let aad: Vec<u8> = aad.into_iter().collect();
        Aad(Cow::Owned(aad))
    }

    /// Constructs a borrowed `Aad` from a byte slice — no allocation.
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Aad(Cow::Borrowed(slice))
    }

    /// Returns the underlying bytes of the associated data.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns `true` if the associated data is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts a borrowed `Aad` into an owned one, copying the bytes if
    /// necessary. The result borrows nothing, so it can outlive the input —
    /// which is what lets the sequence and map sub-ciphers hold the AAD they
    /// were constructed with for the lifetime of the builder chain.
    pub fn into_owned(self) -> Aad<'static> {
        match self.0 {
            Cow::Borrowed(slice) => Aad(Cow::Owned(slice.to_vec())),
            Cow::Owned(owned) => Aad(Cow::Owned(owned)),
        }
    }

    /// Pre-Authentication Encoding of a list of byte pieces (from the PASETO
    /// spec): `LE64(count) || (LE64(len(piece)) || piece)*`. Structurally
    /// distinct inputs always encode to distinct byte strings, so this is the
    /// building block upstream crates use to define their own domain-separated
    /// composite AAD shapes (see [`IntoAad`]).
    pub fn pae(pieces: &[&[u8]]) -> Self {
        pae::encode(pieces)
    }

    /// Derives the AAD a map entry's value must be sealed against, binding the
    /// entry `key` to this (caller-supplied) AAD.
    ///
    /// Map keys travel in the clear inside a ciphertext container, so without
    /// this binding an attacker holding a stored ciphertext could swap or
    /// rename keys undetected, silently reassigning values to different
    /// fields. [`MapCipher::encrypt_value`](crate::MapCipher::encrypt_value)
    /// and [`MapAccess::next_entry`](crate::MapAccess::next_entry)
    /// implementations are required to derive each entry's effective AAD
    /// through this method — both sides must use it, or nothing decrypts.
    ///
    /// The encoding is `PAE(domain, aad, key)`. The leading domain-separation
    /// label keeps the result disjoint from user-supplied composite AAD: a
    /// caller binding the tuple `(aad, key)` at the top level (e.g. via
    /// [`ContextTag`](crate::ContextTag)) encodes `PAE(aad, key)`, which can
    /// never collide with a map entry's three-piece, labelled encoding.
    pub fn for_map_entry(&self, key: &str) -> Aad<'static> {
        const MAP_ENTRY_DOMAIN: &[u8] = b"vitaminc/aead/map-entry/v1";
        pae::encode(&[MAP_ENTRY_DOMAIN, self.as_bytes(), key.as_bytes()])
    }

    /// Derives the AAD a structural marker must be sealed against.
    ///
    /// Markers are sealed empty plaintexts whose tag is the only thing
    /// authenticating a structural fact — "this sequence is empty", "this
    /// map is empty", "this value is absent". Like [`for_map_entry`], the
    /// encoding is a labelled three-piece `PAE(domain, aad, kind)`: the
    /// leading domain label keeps marker AAD disjoint from user-supplied
    /// composite AAD (a two-piece `PAE(label, aad)` would collide with a
    /// caller binding the tuple `(label, aad)` at the top level), and the
    /// `kind` piece keeps the marker kinds disjoint from each other, so a
    /// stored marker can never be replayed as a different structural claim.
    ///
    /// [`Cipher::encrypt_none`](crate::Cipher::encrypt_none),
    /// [`SeqCipher::end`](crate::SeqCipher::end) and
    /// [`MapCipher::end`](crate::MapCipher::end) implementations are
    /// required to derive marker AAD through these methods — both sides
    /// must use them, or nothing decrypts.
    ///
    /// [`for_map_entry`]: Aad::for_map_entry
    fn for_marker(&self, kind: &[u8]) -> Aad<'static> {
        const MARKER_DOMAIN: &[u8] = b"vitaminc/aead/marker/v1";
        pae::encode(&[MARKER_DOMAIN, self.as_bytes(), kind])
    }

    /// Derives the effective AAD every leaf is sealed against, binding the
    /// wire-format `version` byte that prefixes the stored leaf
    /// ([`WIRE_VERSION`](crate::WIRE_VERSION)).
    ///
    /// This is the outermost derivation: ciphers apply it at the AEAD
    /// seal/open boundary, *after* any structural derivation
    /// ([`for_map_entry`](Aad::for_map_entry),
    /// [`for_sequence_element`](Aad::for_sequence_element), the markers) has
    /// produced the caller-visible AAD. Binding the version under the tag is
    /// what makes it more than a parse hint: a stored leaf relabeled with a
    /// different version byte fails verification instead of selecting a
    /// different (perhaps weaker) set of parsing and derivation rules — the
    /// downgrade is foreclosed by construction.
    ///
    /// The domain label deliberately carries no `/v1` suffix: the version is
    /// a *parameter* here, not part of the label.
    pub fn for_leaf(&self, version: u8) -> Aad<'static> {
        const LEAF_DOMAIN: &[u8] = b"vitaminc/aead/leaf";
        pae::encode(&[LEAF_DOMAIN, &[version], self.as_bytes()])
    }

    /// Derives the AAD a sequence element must be sealed against.
    ///
    /// Without this derivation, sequence elements share the caller's bare
    /// AAD with a top-level `Single` — byte-identical — so an attacker
    /// holding a stored ciphertext could rewrap a `Single` leaf as a
    /// one-element `Sequence` (or nest an `EmptySequence` marker one level
    /// deeper) and the self-describing decrypt path would verify it: the
    /// container *shape* was never authenticated. Sealing elements against
    /// a labelled derivation forecloses every such re-homing — a leaf
    /// verifies only in the position it was sealed for.
    ///
    /// Like [`for_map_entry`](Aad::for_map_entry), the encoding is a
    /// labelled three-piece `PAE(domain, aad, kind)` so it can never
    /// collide with a caller's tuple AAD — the same reasoning the marker
    /// derivations behind [`for_empty_sequence`](Aad::for_empty_sequence)
    /// and [`for_empty_map`](Aad::for_empty_map) follow.
    ///
    /// The element *index* is deliberately not bound: records are retrieved
    /// in a different order than they were inserted, so element order is a
    /// caller obligation, not an authenticated fact. Explicit sequence
    /// commitment is tracked separately.
    ///
    /// [`SeqCipher::encrypt_next`](crate::SeqCipher::encrypt_next) and
    /// [`SeqAccess::next_element`](crate::SeqAccess::next_element)
    /// implementations are required to derive each element's effective AAD
    /// through this method — both sides must use it, or nothing decrypts.
    pub fn for_sequence_element(&self) -> Aad<'static> {
        const SEQ_ELEMENT_DOMAIN: &[u8] = b"vitaminc/aead/seq-element/v1";
        pae::encode(&[SEQ_ELEMENT_DOMAIN, self.as_bytes(), b"element"])
    }

    /// Marker AAD for an empty sequence.
    ///
    /// Thin wrapper over the private `for_marker` derivation — this method
    /// and its siblings are its public surface, one per marker kind, so a
    /// stored marker can never be replayed as a different structural claim.
    pub fn for_empty_sequence(&self) -> Aad<'static> {
        self.for_marker(b"empty-sequence")
    }

    /// Marker AAD for an empty map.
    pub fn for_empty_map(&self) -> Aad<'static> {
        self.for_marker(b"empty-map")
    }

    /// Marker AAD for an authenticated absent value (`Option::None`).
    ///
    /// Domain separation here is what stops a `Single` leaf sealed under the
    /// bare AAD from being re-tagged as a `None` marker (silent authenticated
    /// data deletion) — and, symmetrically, an absence marker from validating
    /// as an encrypted empty byte string.
    pub fn for_none(&self) -> Aad<'static> {
        self.for_marker(b"none")
    }
}

/// Types that can be canonically converted into an [`Aad`].
///
/// Implementations are provided for common shapes (byte slices, strings,
/// integers, tuples, options). Composite implementations use Pre-Authentication
/// Encoding (PAE) so structurally distinct inputs always encode to distinct
/// byte strings.
///
/// A context has two views. [`into_aad`](Self::into_aad) gives the bytes
/// the AEAD authenticates. [`into_aad_piece`](Self::into_aad_piece) gives
/// the same context as an [`AadPiece`] tree, for a consumer that needs to
/// know what those bytes were built from (a log, an audit trail, a
/// structured binding). `into_aad_piece` has a default that returns the
/// whole encoding as one opaque `Bytes` leaf, so a type that implements
/// only `into_aad` keeps compiling and working. Override it to expose
/// structure.
///
/// An override must keep the two views consistent: `x.into_aad_piece().into_aad()`
/// must be byte-for-byte `x.into_aad()`, and if the type is also a PRF
/// context, `x.into_aad_piece().into_prf_context()` must equal
/// `x.into_prf_context()`. In other words, the tree is the same context as
/// the value (see [`AadPiece`]). Every built-in type follows this, checked
/// by quickcheck.
///
/// ```rust
/// use std::borrow::Cow;
/// use vitaminc_aead::{Aad, AadPiece, IntoAad};
///
/// // Bytes only: the parts view is the encoding as one opaque leaf.
/// struct Opaque;
/// impl<'a> IntoAad<'a> for Opaque {
///     fn into_aad(self) -> Aad<'a> {
///         "opaque".into_aad()
///     }
/// }
/// assert_eq!(
///     Opaque.into_aad_piece(),
///     AadPiece::Bytes(Cow::Borrowed(b"opaque")),
/// );
///
/// // Structured: override the parts view, and keep the bytes identical.
/// struct TenantId(u64);
/// impl<'a> IntoAad<'a> for TenantId {
///     fn into_aad(self) -> Aad<'a> {
///         ("tenant", self.0).into_aad()
///     }
///     fn into_aad_piece(self) -> AadPiece<'a> {
///         ("tenant", self.0).into_aad_piece()
///     }
/// }
/// let id = TenantId(7);
/// assert_eq!(id.into_aad_piece().to_string(), "(\"tenant\", 7u64)");
/// assert_eq!(
///     TenantId(7).into_aad_piece().into_aad().as_bytes(),
///     TenantId(7).into_aad().as_bytes(),
/// );
/// ```
pub trait IntoAad<'a> {
    /// Convert `self` into an [`Aad`].
    fn into_aad(self) -> Aad<'a>
    where
        Self: Sized;

    /// Describe `self` as an [`AadPiece`] tree that encodes to the same
    /// bytes as [`into_aad`](Self::into_aad).
    ///
    /// Provided: the whole encoding as a single [`AadPiece::Bytes`] leaf,
    /// which is always correct and never exposes structure. Override it to
    /// name the parts.
    fn into_aad_piece(self) -> AadPiece<'a>
    where
        Self: Sized,
    {
        AadPiece::Bytes(self.into_aad().0)
    }
}

// `Aad` deliberately does NOT implement `MaybeEmpty`: an already-encoded AAD can
// only be judged on its bytes, and PAE framing makes a composite built from
// empty parts (`Some("")`, `("", "")`) non-empty as bytes — so `NonEmpty<Aad>`
// would certify exactly the degenerate value it exists to exclude. Prove
// non-emptiness on the raw value, before it is framed, then convert:
// `NonEmpty<T>` where `T: IntoAad`.

/// `NonEmpty<T>` is transparent: it encodes exactly as `T` does. The wrapper
/// changes what the type promises, never the bytes authenticated.
impl<'a, T> IntoAad<'a> for NonEmpty<T>
where
    T: IntoAad<'a>,
{
    fn into_aad(self) -> Aad<'a> {
        self.into_inner().into_aad()
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        self.into_inner().into_aad_piece()
    }
}

/// Self type is already an Aad
impl<'a> IntoAad<'a> for Aad<'a> {
    fn into_aad(self) -> Aad<'a> {
        self
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Bytes(self.0)
    }
}

/// Used for an "empty" AAD
impl<'a> IntoAad<'a> for () {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(&[])
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Unit
    }
}

impl<'a> IntoAad<'a> for &'a [u8] {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(self)
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Bytes(Cow::Borrowed(self))
    }
}

impl<'a> IntoAad<'a> for Vec<u8> {
    fn into_aad(self) -> Aad<'a> {
        Aad::new_owned(self)
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Bytes(Cow::Owned(self))
    }
}

impl<'a, const N: usize> IntoAad<'a> for [u8; N] {
    fn into_aad(self) -> Aad<'a> {
        Aad::new_owned(self)
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Bytes(Cow::Owned(self.to_vec()))
    }
}

impl<'a, const N: usize> IntoAad<'a> for &'a [u8; N] {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(self.as_slice())
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Bytes(Cow::Borrowed(self.as_slice()))
    }
}

impl<'a> IntoAad<'a> for String {
    fn into_aad(self) -> Aad<'a> {
        Aad::new_owned(self.into_bytes())
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Text(Cow::Owned(self))
    }
}

impl<'a> IntoAad<'a> for Cow<'a, [u8]> {
    fn into_aad(self) -> Aad<'a> {
        Aad(self)
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Bytes(self)
    }
}

impl<'a> IntoAad<'a> for &'a str {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(self.as_bytes())
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::Text(Cow::Borrowed(self))
    }
}

macro_rules! integer_aad {
    ($($ty:ty => $variant:ident),+ $(,)?) => {$(
        /// An integer encodes as its raw little-endian bytes, with no type
        /// tag — matching the original `u64` wire format. Distinct integer
        /// types of the same width therefore encode identically; compose a
        /// tuple (PAE-framed) when that distinction must be authenticated.
        impl<'a> IntoAad<'a> for $ty {
            fn into_aad(self) -> Aad<'a> {
                Aad::new_owned(self.to_le_bytes())
            }

            /// The integer as its own [`AadPiece`] variant, so the parts
            /// view keeps the type the encoding drops.
            fn into_aad_piece(self) -> AadPiece<'a> {
                AadPiece::$variant(self)
            }
        }
    )+};
}

integer_aad!(
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
);

impl<'a, T> IntoAad<'a> for Option<T>
where
    T: IntoAad<'a>,
{
    fn into_aad(self) -> Aad<'a> {
        match self {
            Some(value) => Aad::pae(&[value.into_aad().as_bytes()]),
            None => Aad::pae(&[]),
        }
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        AadPiece::List(self.into_iter().map(T::into_aad_piece).collect())
    }
}

impl<'a, A, B> IntoAad<'a> for (A, B)
where
    A: IntoAad<'a>,
    B: IntoAad<'a>,
{
    fn into_aad(self) -> Aad<'a> {
        let (a, b) = self;
        let a = a.into_aad();
        let b = b.into_aad();
        Aad::pae(&[a.as_bytes(), b.as_bytes()])
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        let (a, b) = self;
        AadPiece::List(vec![a.into_aad_piece(), b.into_aad_piece()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_is_transparent_to_the_encoding() {
        assert_eq!(
            NonEmpty::new("users/email")
                .expect("non-empty")
                .into_aad()
                .as_bytes(),
            "users/email".into_aad().as_bytes()
        );
        assert_eq!(
            Some(NonEmpty::new("users/email").expect("non-empty"))
                .into_aad()
                .as_bytes(),
            Some("users/email").into_aad().as_bytes()
        );
        assert_eq!(
            NonEmpty::new(("users", "email"))
                .expect("non-empty")
                .into_aad()
                .as_bytes(),
            ("users", "email").into_aad().as_bytes()
        );
        // A pair extended from a proven head encodes as the bare pair.
        assert_eq!(
            vitaminc_protected::nonempty!("users/email")
                .with(42u64)
                .into_aad()
                .as_bytes(),
            ("users/email", 42u64).into_aad().as_bytes()
        );
        assert_eq!(
            vitaminc_protected::nonempty!("users/email")
                .into_aad()
                .as_bytes(),
            b"users/email"
        );
    }

    #[test]
    fn encoded_aad_reports_emptiness_of_its_bytes_only() {
        assert!(Aad::empty().is_empty());
        assert!("".into_aad().is_empty());
        assert!(!Aad::from_slice(b"raw").is_empty());
        // Composite framing makes an encoded empty value non-empty as bytes —
        // which is exactly why `Aad` has no `MaybeEmpty` impl: the structural
        // check belongs before encoding (`NonEmpty<T>` where `T: IntoAad`).
        assert!(!Some("").into_aad().is_empty());
    }

    #[test]
    fn test_aad() {
        let aad = Aad::new_owned(vec![1, 2, 3]);
        assert_eq!(aad.as_bytes(), &[1, 2, 3]);
        assert!(!aad.is_empty());

        let aad_borrowed = Aad::from_slice(&[4, 5, 6]);
        assert_eq!(aad_borrowed.as_bytes(), &[4, 5, 6]);
        assert!(!aad_borrowed.is_empty());
    }

    #[test]
    fn test_str_aad() {
        let aad = "hello".into_aad();
        assert_eq!(aad.as_bytes(), b"hello");
        assert!(!aad.is_empty());
    }

    #[test]
    fn test_string_aad() {
        let aad = String::from("world").into_aad();
        assert_eq!(aad.as_bytes(), b"world");
        assert!(!aad.is_empty());
    }

    #[test]
    fn test_u64_aad() {
        let aad = 42u64.into_aad();
        assert_eq!(aad.as_bytes(), &[42, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!aad.is_empty());
    }

    #[test]
    fn every_integer_type_encodes_as_little_endian_bytes() {
        assert_eq!(7u8.into_aad().as_bytes(), &7u8.to_le_bytes());
        assert_eq!(7u16.into_aad().as_bytes(), &7u16.to_le_bytes());
        assert_eq!(7u32.into_aad().as_bytes(), &7u32.to_le_bytes());
        assert_eq!(7u64.into_aad().as_bytes(), &7u64.to_le_bytes());
        assert_eq!(7u128.into_aad().as_bytes(), &7u128.to_le_bytes());
        assert_eq!((-7i8).into_aad().as_bytes(), &(-7i8).to_le_bytes());
        assert_eq!((-7i16).into_aad().as_bytes(), &(-7i16).to_le_bytes());
        assert_eq!((-7i32).into_aad().as_bytes(), &(-7i32).to_le_bytes());
        assert_eq!((-7i64).into_aad().as_bytes(), &(-7i64).to_le_bytes());
        assert_eq!((-7i128).into_aad().as_bytes(), &(-7i128).to_le_bytes());
        // Widths keep the types apart even without a tag.
        assert_ne!(7u32.into_aad().as_bytes(), 7u64.into_aad().as_bytes());
    }

    #[test]
    fn test_tuple_aad() {
        let aad = ("foo", "bar").into_aad();
        let expected = Aad::pae(&[b"foo", b"bar"]);
        assert_eq!(aad.as_bytes(), expected.as_bytes());
        assert!(!aad.is_empty());
    }

    #[test]
    fn test_option_none_differs_from_some_empty() {
        let none_aad = Option::<&str>::None.into_aad();
        let some_empty_aad = Some("").into_aad();
        assert_ne!(none_aad.as_bytes(), some_empty_aad.as_bytes());
    }

    #[test]
    fn test_option_none_differs_from_unit() {
        let none_aad = Option::<&str>::None.into_aad();
        let unit_aad = ().into_aad();
        assert_ne!(none_aad.as_bytes(), unit_aad.as_bytes());
    }

    #[test]
    fn test_option_some_roundtrips_value() {
        let some_aad = Some("hello").into_aad();
        let expected = Aad::pae(&[b"hello"]);
        assert_eq!(some_aad.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn test_byte_array_aad() {
        let aad = [1u8, 2, 3].into_aad();
        assert_eq!(aad.as_bytes(), &[1, 2, 3]);
        assert!(!aad.is_empty());
    }

    #[test]
    fn test_byte_array_ref_aad() {
        let arr = [4u8, 5, 6];
        let aad = (&arr).into_aad();
        assert_eq!(aad.as_bytes(), &[4, 5, 6]);
    }

    #[test]
    fn test_option_byte_array_aad() {
        let some_aad = Some([1u8, 2, 3]).into_aad();
        let expected = Aad::pae(&[&[1, 2, 3]]);
        assert_eq!(some_aad.as_bytes(), expected.as_bytes());

        let none_aad = Option::<[u8; 3]>::None.into_aad();
        // `None` is PAE-encoded as zero pieces: LE64(0) = 8 zero bytes.
        assert_eq!(none_aad.as_bytes(), &[0u8; 8]);
        assert_ne!(none_aad.as_bytes(), some_aad.as_bytes());
    }

    #[test]
    fn for_map_entry_pins_encoding() {
        // The exact bytes are a wire-format commitment: PAE(domain, aad, key).
        // Changing them breaks decryption of existing ciphertexts.
        let bound = Aad::from_slice(b"ctx").for_map_entry("name");
        let expected = Aad::pae(&[b"vitaminc/aead/map-entry/v1", b"ctx", b"name"]);
        assert_eq!(bound.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn for_map_entry_differs_from_tuple_aad() {
        // The domain label keeps map-entry AAD disjoint from a user binding
        // the same (aad, key) pair as tuple AAD at the top level.
        let bound = Aad::from_slice(b"ctx").for_map_entry("name");
        let tuple = (Aad::from_slice(b"ctx"), "name").into_aad();
        assert_ne!(bound.as_bytes(), tuple.as_bytes());
    }

    #[test]
    fn marker_aads_pin_encoding() {
        // The exact bytes are a wire-format commitment: PAE(domain, aad, kind).
        // Changing them breaks decryption of existing markers.
        let aad = Aad::from_slice(b"ctx");
        for (derived, kind) in [
            (aad.for_empty_sequence(), b"empty-sequence".as_slice()),
            (aad.for_empty_map(), b"empty-map"),
            (aad.for_none(), b"none"),
        ] {
            let expected = Aad::pae(&[b"vitaminc/aead/marker/v1", b"ctx", kind]);
            assert_eq!(derived.as_bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn marker_aads_differ_from_tuple_aad_and_each_other() {
        // The domain label keeps marker AAD disjoint from a user binding a
        // matching (label, aad) tuple at the top level, and the kind piece
        // keeps the three markers disjoint from one another.
        let aad = Aad::from_slice(b"ctx");
        let markers = [
            aad.for_empty_sequence(),
            aad.for_empty_map(),
            aad.for_none(),
        ];
        for (i, m) in markers.iter().enumerate() {
            let tuple = (
                b"vitaminc/aead/marker/v1".as_slice(),
                Aad::from_slice(b"ctx"),
            )
                .into_aad();
            assert_ne!(m.as_bytes(), tuple.as_bytes());
            for other in &markers[i + 1..] {
                assert_ne!(m.as_bytes(), other.as_bytes());
            }
        }
    }

    #[test]
    fn for_leaf_pins_encoding() {
        // The exact bytes are a wire-format commitment: PAE(domain, [ver], aad).
        // Changing them breaks decryption of every existing leaf.
        let derived = Aad::from_slice(b"ctx").for_leaf(1);
        let expected = Aad::pae(&[b"vitaminc/aead/leaf", &[1u8], b"ctx"]);
        assert_eq!(derived.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn for_leaf_is_version_sensitive_and_disjoint() {
        let aad = Aad::from_slice(b"ctx");
        // A relabeled version byte must change the effective AAD — that is
        // the whole downgrade defence.
        assert_ne!(aad.for_leaf(1).as_bytes(), aad.for_leaf(2).as_bytes());
        // Disjoint from the bare AAD and from a caller tuple binding the
        // same shape at the top level.
        assert_ne!(aad.for_leaf(1).as_bytes(), aad.as_bytes());
        let tuple = (b"vitaminc/aead/leaf".as_slice(), "ctx").into_aad();
        assert_ne!(aad.for_leaf(1).as_bytes(), tuple.as_bytes());
    }

    #[test]
    fn for_sequence_element_pins_encoding() {
        // The exact bytes are a wire-format commitment: PAE(domain, aad, kind).
        // Changing them breaks decryption of existing sequence ciphertexts.
        let derived = Aad::from_slice(b"ctx").for_sequence_element();
        let expected = Aad::pae(&[b"vitaminc/aead/seq-element/v1", b"ctx", b"element"]);
        assert_eq!(derived.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn for_sequence_element_differs_from_bare_aad_and_sibling_derivations() {
        // The whole point: a leaf sealed at the top level (bare AAD), as a
        // map entry, or as a marker must never verify in element position.
        let aad = Aad::from_slice(b"ctx");
        let elem = aad.for_sequence_element();
        assert_ne!(elem.as_bytes(), aad.as_bytes());
        assert_ne!(elem.as_bytes(), aad.for_map_entry("element").as_bytes());
        assert_ne!(elem.as_bytes(), aad.for_empty_sequence().as_bytes());
        assert_ne!(elem.as_bytes(), aad.for_none().as_bytes());
        // And it must not collide with a caller binding a matching tuple.
        let tuple = (b"vitaminc/aead/seq-element/v1".as_slice(), "ctx").into_aad();
        assert_ne!(elem.as_bytes(), tuple.as_bytes());
    }

    #[test]
    fn for_map_entry_is_key_sensitive() {
        let aad = Aad::from_slice(b"ctx");
        assert_ne!(
            aad.for_map_entry("a").as_bytes(),
            aad.for_map_entry("b").as_bytes()
        );
        // Moving bytes between AAD and key must not collide (PAE injectivity).
        assert_ne!(
            Aad::from_slice(b"ctxa").for_map_entry("").as_bytes(),
            Aad::from_slice(b"ctx").for_map_entry("a").as_bytes()
        );
    }

    #[test]
    fn test_tuple_aad_is_injective() {
        // ("ab", "cd") != ("a", "bcd")
        let aad1 = ("ab", "cd").into_aad();
        let aad2 = ("a", "bcd").into_aad();
        assert_ne!(aad1.as_bytes(), aad2.as_bytes());

        // ("foobar", ()) != ("foo", "bar")
        let aad3 = ("foobar", ()).into_aad();
        let aad4 = ("foo", "bar").into_aad();
        assert_ne!(aad3.as_bytes(), aad4.as_bytes());
    }
}
