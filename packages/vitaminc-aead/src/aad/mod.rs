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

    /// Converts a borrowed `Aad` into an owned one, copying the bytes if necessary.
    pub fn into_owned(self) -> Aad<'a> {
        match self.0 {
            x @ Cow::Borrowed(_) => Self(x.into_owned().into()),
            Cow::Owned(_) => self,
        }
    }

    pub(crate) fn pae(pieces: &[&[u8]]) -> Self {
        pae::encode(pieces)
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
