mod pae;

use std::borrow::Cow;

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

    pub(crate) fn pae(pieces: &[&[u8]]) -> Self {
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

    /// Marker AAD for an empty sequence — see [`for_marker`](Aad::for_marker)
    /// (private; this method and its siblings are the public surface).
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
pub trait IntoAad<'a> {
    /// Convert `self` into an [`Aad`].
    fn into_aad(self) -> Aad<'a>
    where
        Self: Sized;
}

/// Self type is already an Aad
impl<'a> IntoAad<'a> for Aad<'a> {
    fn into_aad(self) -> Aad<'a> {
        self
    }
}

/// Used for an "empty" AAD
impl<'a> IntoAad<'a> for () {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(&[])
    }
}

impl<'a> IntoAad<'a> for &'a [u8] {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(self)
    }
}

impl<'a> IntoAad<'a> for Vec<u8> {
    fn into_aad(self) -> Aad<'a> {
        Aad::new_owned(self)
    }
}

impl<'a, const N: usize> IntoAad<'a> for [u8; N] {
    fn into_aad(self) -> Aad<'a> {
        Aad::new_owned(self)
    }
}

impl<'a, const N: usize> IntoAad<'a> for &'a [u8; N] {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(self.as_slice())
    }
}

impl<'a> IntoAad<'a> for String {
    fn into_aad(self) -> Aad<'a> {
        Aad::new_owned(self.into_bytes())
    }
}

impl<'a> IntoAad<'a> for Cow<'a, [u8]> {
    fn into_aad(self) -> Aad<'a> {
        Aad(self)
    }
}

impl<'a> IntoAad<'a> for &'a str {
    fn into_aad(self) -> Aad<'a> {
        Aad::from_slice(self.as_bytes())
    }
}

impl<'a> IntoAad<'a> for u64 {
    fn into_aad(self) -> Aad<'a> {
        let bytes = self.to_le_bytes();
        Aad::new_owned(bytes)
    }
}

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
