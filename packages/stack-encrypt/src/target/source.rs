//! How an [`Encryption`](super::Encryption) receives its plaintext. The
//! explanation is on [`SourceMode`], which is what the public docs show; this
//! module is private and its items are re-exported from `target`.

use vitaminc_protected::OpaqueDebug;

/// A description's plaintext is handed to it by reference: the default mode,
/// and the one a record runs each field in when it takes the field out of a
/// borrowed struct. Every operation reads the plaintext in place.
///
/// This is a mode, not a value: the enum is uninhabited, so no `Borrowed`
/// ever exists and it never holds a plaintext. Its `Debug` can print nothing.
#[derive(Debug)]
pub enum Borrowed {}

/// A description's plaintext is handed to it by value. The description
/// reads it without a copy, and wipes it or moves it into the output.
///
/// Uninhabited like [`Borrowed`]: a mode that never holds the plaintext. The
/// value itself lives only inside the description's closure, which has no
/// `Debug`, and in the [`Pending`](super::Pending) output.
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
/// An operation reads the plaintext in place. It never needs a copy, so no
/// mode asks for `Clone`. A description can be handed the plaintext two ways,
/// and because the mode is a type parameter the difference is settled at
/// compile time:
///
/// - [`Borrowed`], the default: the description is handed `&S`. This is
///   what [`EncryptTarget::encryption`](super::EncryptTarget::encryption)
///   describes, and what lets a record pick its fields out of a borrowed
///   struct. The plaintext stays with the caller, who wipes it.
/// - [`Owned`]: the description is handed `S` itself, through
///   [`KeysetCipher::run`](crate::KeysetCipher::run). The operation that is
///   handed the value reads it and then lets go of it: a ciphertext and a
///   term wipe it through Vitamin C, and a passthrough moves it into the
///   output. Several operations over one owned value
///   ([`zip`](super::Encryption::zip)) read it in place first, and the one
///   written first is handed the value.
///
/// The trait is sealed: these two modes are the only ones.
pub trait SourceMode<'s, S: 's>: sealed::Sealed + 's {
    /// What the description is handed: `&'s S` or `S`.
    type Source;
    /// The source as the engine passes it between descriptions.
    #[doc(hidden)]
    fn source(source: Self::Source) -> Source<'s, S>;
}

/// A plaintext on its way to an operation: a borrow of it, or the value.
///
/// The mode of a description says which one it is handed, so the two are
/// never confused: a [`Borrowed`] description is handed a borrow, and an
/// [`Owned`] one the value. This type exists so that one owned value can be
/// lent to several descriptions and then handed to the last.
#[doc(hidden)]
#[derive(OpaqueDebug)]
pub struct Source<'b, S>(Held<'b, S>);

/// What a [`Source`] holds.
pub(crate) enum Held<'b, S> {
    Lent(&'b S),
    Given(S),
}

impl<'b, S> Source<'b, S> {
    pub(crate) fn lent(source: &'b S) -> Self {
        Self(Held::Lent(source))
    }
    pub(crate) fn given(source: S) -> Self {
        Self(Held::Given(source))
    }
    /// Read the plaintext in place.
    pub(crate) fn view(&self) -> &S {
        match &self.0 {
            Held::Lent(source) => source,
            Held::Given(source) => source,
        }
    }
    /// Lend the plaintext to another description, keeping this source.
    pub(crate) fn lend(&self) -> Source<'_, S> {
        Source::lent(self.view())
    }
    /// Let go of the plaintext after reading it in place. A value the
    /// description was given is handed to `wipe`. A borrow is the
    /// caller's, and nothing is done.
    pub(crate) fn release(self, wipe: impl FnOnce(S)) {
        if let Held::Given(source) = self.0 {
            wipe(source);
        }
    }
    /// The borrow or the value, for an operation that treats them
    /// differently.
    pub(crate) fn into_held(self) -> Held<'b, S> {
        self.0
    }
    /// The borrow a [`Borrowed`] description is handed.
    pub(crate) fn borrowed(self) -> &'b S {
        match self.0 {
            Held::Lent(source) => source,
            Held::Given(_) => unreachable!("a borrowed description is handed a borrow"),
        }
    }
    /// The value an [`Owned`] description is handed.
    pub(crate) fn owned(self) -> S {
        match self.0 {
            Held::Given(source) => source,
            Held::Lent(_) => unreachable!("an owned description is handed its value"),
        }
    }
}

impl<'s, S: 's> SourceMode<'s, S> for Borrowed {
    type Source = &'s S;
    fn source(source: Self::Source) -> Source<'s, S> {
        Source::lent(source)
    }
}

impl<'s, S: 's> SourceMode<'s, S> for Owned {
    type Source = S;
    fn source(source: Self::Source) -> Source<'s, S> {
        Source::given(source)
    }
}

/// A mode in which an operation that seals or indexes the plaintext can let
/// go of it. Every such operation asks for it, and
/// [`passthrough`](super::passthrough) does not.
///
/// - [`Borrowed`] always can: the plaintext is the caller's, and the
///   operation leaves it there.
/// - [`Owned`] can when `S` is `Zeroize`. The operation that is handed the
///   value wipes it on every path: once it has read the value, and when the
///   context is refused or an operation fails.
///
/// So in `Owned` mode a plaintext that is sealed or indexed is `Zeroize`,
/// and in `Borrowed` mode it need not be.
pub trait WipeSource<'s, S: 's>: SourceMode<'s, S> {
    /// Let go of the plaintext. A value is wiped, and a borrow is left with
    /// the caller.
    #[doc(hidden)]
    fn wipe(source: Source<'_, S>);
}
impl<'s, S: 's> WipeSource<'s, S> for Borrowed {
    // A borrow is the caller's: letting go of it does nothing.
    fn wipe(_: Source<'_, S>) {}
}
impl<'s, S: zeroize::Zeroize + 's> WipeSource<'s, S> for Owned {
    fn wipe(source: Source<'_, S>) {
        source.release(|value| drop(vitaminc_protected::Protected::new(value)));
    }
}

/// A source that is wiped if it is dropped before an operation takes it.
/// An operation that reads an owned value before handing it on holds it in
/// one, so a reader that panics still lets the value go through
/// [`WipeSource::wipe`]: a value is wiped, and a borrow is left alone.
pub(crate) struct Guarded<'b, 's, M: WipeSource<'s, S>, S: 's> {
    source: Option<Source<'b, S>>,
    mode: std::marker::PhantomData<fn() -> (M, &'s ())>,
}

impl<'b, 's, M: WipeSource<'s, S>, S: 's> Guarded<'b, 's, M, S> {
    pub(crate) fn new(source: Source<'b, S>) -> Self {
        Self {
            source: Some(source),
            mode: std::marker::PhantomData,
        }
    }
    /// The source, to read in place.
    pub(crate) fn source(&self) -> &Source<'b, S> {
        match &self.source {
            Some(source) => source,
            None => unreachable!("a guard holds its source until it is taken"),
        }
    }
    /// Hand the source on: the guard no longer wipes it.
    pub(crate) fn take(mut self) -> Source<'b, S> {
        match self.source.take() {
            Some(source) => source,
            None => unreachable!("a guard holds its source until it is taken"),
        }
    }
}

impl<'s, M: WipeSource<'s, S>, S: 's> Drop for Guarded<'_, 's, M, S> {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            M::wipe(source);
        }
    }
}

/// A mode in which an operation can take the plaintext by value. Only
/// [`passthrough`](super::passthrough) asks for it, because its output is
/// the plaintext itself. [`Owned`] always can: the value is moved. In
/// [`Borrowed`] mode the value is the caller's, so the output is a copy of
/// it, and `S` must be `Clone`. A passthrough is stored in the clear, so
/// that copy is not a copy of a secret.
pub trait ConsumeSource<'s, S: 's>: SourceMode<'s, S> {
    /// The plaintext, by value.
    #[doc(hidden)]
    fn take(source: Source<'_, S>) -> S;
}
impl<'s, S: Clone + 's> ConsumeSource<'s, S> for Borrowed {
    fn take(source: Source<'_, S>) -> S {
        source.borrowed().clone()
    }
}
impl<'s, S: 's> ConsumeSource<'s, S> for Owned {
    fn take(source: Source<'_, S>) -> S {
        source.owned()
    }
}

#[cfg(test)]
mod tests {
    use super::Source;

    /// A source's `Debug` masks what it holds, lent or given.
    #[test]
    fn a_source_prints_no_plaintext() {
        let secret = String::from("4111 1111 1111 1111");
        let lent = format!("{:?}", Source::lent(&secret));
        let given = format!("{:?}", Source::given(secret.clone()));
        for printed in [lent, given] {
            assert!(!printed.contains("4111"), "{printed}");
            assert!(printed.contains("***"), "{printed}");
        }
    }
}
