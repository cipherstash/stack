use std::borrow::Cow;

pub struct Aad<'a>(Cow<'a, [u8]>);

impl<'a> Aad<'a> {
    pub fn empty() -> Self {
        Aad(Cow::Borrowed(&[]))
    }

    pub fn new_owned<I>(aad: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        // Collect the iterator into a Vec<u8>
        let aad: Vec<u8> = aad.into_iter().collect();
        // Convert the Vec<u8> into a Cow<[u8]>
        // and wrap it in Aad
        Aad(Cow::Owned(aad))
    }

    pub fn from_slice(slice: &'a [u8]) -> Self {
        Aad(Cow::Borrowed(slice))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_owned(self) -> Aad<'a> {
        match self.0 {
            x @ Cow::Borrowed(_) => Self(x.into_owned().into()),
            Cow::Owned(_) => self,
        }
    }
}

impl<'a> Extend<u8> for Aad<'a> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.0.to_mut().extend(iter);
    }
}

pub trait IntoAad<'a> {
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
            Some(value) => value.into_aad(),
            None => Aad::empty(),
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
        let mut a = a.into_aad();
        let b = b.into_aad();
        let iter = b.0.iter().cloned();
        a.extend(iter);
        a
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
        assert_eq!(aad.as_bytes(), b"foobar");
        assert!(!aad.is_empty());
    }
}
