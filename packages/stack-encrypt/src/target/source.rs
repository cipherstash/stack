//! How an [`Encryption`](super::Encryption) receives its plaintext. The
//! explanation is on [`SourceMode`], which is what the public docs show; this
//! module is private and its items are re-exported from `target`.

/// A description's plaintext is handed to it by reference: the default mode,
/// and the one every [`EncryptFrom`](super::EncryptFrom) declaration runs in.
/// An operation that consumes the plaintext clones it.
#[derive(Debug)]
pub enum Borrowed {}

/// A description's plaintext is handed to it by value. A single operation
/// consumes it without a copy; only fan-out over it needs `Clone`.
#[derive(Debug)]
pub enum Owned {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Borrowed {}
    impl Sealed for super::Owned {}
}

/// How a description receives its plaintext: the `M` parameter of
/// [`Encryption`](super::Encryption).
///
/// Vitamin C's `Encrypt`, `PrfValue` and `CllwOreEncrypt` consume the value
/// they are given, so an operation needs the plaintext by value. A
/// description can be handed it two ways, and because the mode is a type
/// parameter the difference is settled at compile time:
///
/// - [`Borrowed`], the default: the description is handed `&S`. This is what
///   [`encrypt_as`](crate::KeysetCipher::encrypt_as) does for every
///   [`EncryptFrom`](super::EncryptFrom) declaration, and what lets a record
///   pick its fields out of a borrowed struct. An operation that consumes the
///   plaintext clones it first ([`ConsumeSource`]), so here, and only here,
///   `S` must be `Clone`.
/// - [`Owned`]: the description is handed `S` itself, through
///   [`KeysetCipher::run`](crate::KeysetCipher::run). A single operation
///   consumes it with no copy, so a plaintext that is deliberately not
///   `Clone` (one that is moved and wiped, such as a zeroizing FFI value) can
///   be sealed or indexed. Running two operations over one value
///   ([`zip`](super::Encryption::zip)) hands a copy to every side but the
///   last, which takes ownership ([`ShareSource`]); that, and only that,
///   needs `Clone`.
///
/// A match term only reads its text, so it runs in either mode without a
/// copy. The traits are sealed: these two modes are the only ones.
pub trait SourceMode<'s, S: 's>: sealed::Sealed + 's {
    /// What the description is handed: `&'s S` or `S`.
    type Source;
    /// Read the plaintext in place, for an operation that does not consume
    /// it (a match term reads text through `AsRef<str>`).
    fn view(source: &Self::Source) -> &S;
}

/// A mode in which an operation can take the plaintext by value: always for
/// [`Owned`]; for [`Borrowed`] when `S: Clone`, by cloning it.
pub trait ConsumeSource<'s, S: 's>: SourceMode<'s, S> {
    /// The plaintext, by value.
    fn take(source: Self::Source) -> S;
}

/// A mode in which one plaintext can be handed to two operations: always
/// for [`Borrowed`], where the reference is copied; for [`Owned`] when
/// `S: Clone`, where the first side gets a clone and the second the value.
pub trait ShareSource<'s, S: 's>: SourceMode<'s, S> {
    /// The plaintext for the first side, and for the second.
    fn share(source: Self::Source) -> (Self::Source, Self::Source);
}

impl<'s, S: 's> SourceMode<'s, S> for Borrowed {
    type Source = &'s S;
    fn view(source: &Self::Source) -> &S {
        source
    }
}
impl<'s, S: Clone + 's> ConsumeSource<'s, S> for Borrowed {
    fn take(source: Self::Source) -> S {
        source.clone()
    }
}
impl<'s, S: 's> ShareSource<'s, S> for Borrowed {
    fn share(source: Self::Source) -> (Self::Source, Self::Source) {
        (source, source)
    }
}

impl<'s, S: 's> SourceMode<'s, S> for Owned {
    type Source = S;
    fn view(source: &Self::Source) -> &S {
        source
    }
}
impl<'s, S: 's> ConsumeSource<'s, S> for Owned {
    fn take(source: Self::Source) -> S {
        source
    }
}
impl<'s, S: Clone + 's> ShareSource<'s, S> for Owned {
    fn share(source: Self::Source) -> (Self::Source, Self::Source) {
        (source.clone(), source)
    }
}
