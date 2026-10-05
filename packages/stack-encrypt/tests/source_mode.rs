//! How a description receives its plaintext (`target::{Borrowed, Owned}`).
//!
//! Vitamin C's `Encrypt` and `PrfValue` consume their input. A description
//! handed a borrow (the default, and what every `EncryptFrom` declaration
//! runs in) clones before an operation consumes; one handed the value
//! (`Owned`) gives it to the operation. These tests hold the two claims that
//! make owned mode worth having:
//!
//! - a plaintext that is **not `Clone`** runs a single operation — a
//!   ciphertext alone, or one term alone — and the output is the same as the
//!   borrowed path's;
//! - the number of copies is exactly what the mode promises: none for one
//!   owned operation, `n - 1` for an owned `zip` of `n`, one per consuming
//!   operation when borrowed, and none ever for a match term, which only
//!   reads its text.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use stack_encrypt::sem::{EqualityTerm, MatchTerm};
use stack_encrypt::target::{
    ciphertext, equality, matching, AeadContext, Borrowed, CallerContext, Encryption, Owned,
};
use stack_encrypt::{nonempty, Encrypt, NonEmpty, StackCipherText};
use stack_kms::FakeDataKeySource;
use vitaminc_aead::{Cipher, IntoAad};
use vitaminc_prf::{IntoPrfContext, Prf, PrfValue, PrfVisitor};
use vitaminc_protected::{Controlled, Protected};

mod common;
use common::stack_cipher;

const NUMBER: &str = "4111 1111 1111 1111";

fn context() -> NonEmpty<&'static str> {
    nonempty!("cards/number")
}
fn aead() -> AeadContext {
    AeadContext::from(context())
}
fn caller() -> CallerContext {
    CallerContext::from(context())
}

/// A secret that is deliberately not `Clone`: it is moved, never copied, and
/// `Protected` wipes the one copy when it drops. It encrypts, derives terms
/// and reads as text exactly as the `String` it holds does.
struct Secret(Protected<String>);

impl Secret {
    fn new(text: &str) -> Self {
        Self(Protected::new(text.to_string()))
    }
}
impl Encrypt for Secret {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.0.encrypt_with_aad(cipher, aad)
    }
}
impl PrfValue for Secret {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        self.0.prf_visit_with_context(prf, context, visitor)
    }
}
impl AsRef<str> for Secret {
    fn as_ref(&self) -> &str {
        self.0.risky_ref()
    }
}

/// A `String` that counts its clones, so a test can say how many copies of
/// the plaintext a description made.
struct Counted {
    text: String,
    clones: Arc<AtomicUsize>,
}

impl Counted {
    fn new(text: &str) -> (Self, Arc<AtomicUsize>) {
        let clones = Arc::new(AtomicUsize::new(0));
        let value = Self {
            text: text.to_string(),
            clones: clones.clone(),
        };
        (value, clones)
    }
}
impl Clone for Counted {
    fn clone(&self) -> Self {
        let _ = self.clones.fetch_add(1, Ordering::SeqCst);
        Self {
            text: self.text.clone(),
            clones: self.clones.clone(),
        }
    }
}
impl Encrypt for Counted {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.text.encrypt_with_aad(cipher, aad)
    }
}
impl PrfValue for Counted {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        self.text.prf_visit_with_context(prf, context, visitor)
    }
}
impl AsRef<str> for Counted {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

// --- A plaintext that is not `Clone` ----------------------------------------

#[tokio::test]
async fn a_plaintext_that_is_not_clone_seals_through_ciphertext_alone() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let sealed: StackCipherText = keyset
        .run(ciphertext::<_, _, Owned>(), Secret::new(NUMBER), aead())
        .await
        .unwrap();

    let opened: String = cipher.decrypt_as(sealed, aead()).await.unwrap();
    assert_eq!(
        opened, NUMBER,
        "an owned, non-Clone plaintext should seal to a ciphertext that opens to its text"
    );
}

#[tokio::test]
async fn a_plaintext_that_is_not_clone_derives_an_equality_term_alone() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let term: EqualityTerm = keyset
        .run(equality::<_, _, Owned>(), Secret::new(NUMBER), caller())
        .await
        .unwrap();

    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(
        term, expected,
        "an owned equality term should be byte-identical to the same text's term"
    );
}

#[tokio::test]
async fn a_plaintext_that_is_not_clone_derives_a_match_term_alone() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let term: MatchTerm = keyset
        .run(matching::<_, _, Owned, _>(), Secret::new(NUMBER), caller())
        .await
        .unwrap();

    let expected: MatchTerm = keyset.match_terms(NUMBER, context()).await.unwrap();
    assert_eq!(
        term, expected,
        "an owned match term should be byte-identical to the same text's term"
    );
}

/// The case the owned mode exists for: the dynamic value an FFI binding
/// decodes is zeroized on drop and is not `Clone`.
#[cfg(feature = "dynamic")]
#[tokio::test]
async fn a_zeroizing_ffi_value_seals_through_ciphertext_alone() {
    use vitaminc_aead_value::FfiValue;

    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let sealed: StackCipherText = keyset
        .run(
            ciphertext::<_, _, Owned>(),
            FfiValue::String(NUMBER.into()),
            aead(),
        )
        .await
        .unwrap();

    let opened: FfiValue = cipher.decrypt_as(sealed, aead()).await.unwrap();
    let FfiValue::String(text) = opened else {
        panic!("an FfiValue string should open to a string");
    };
    assert_eq!(
        text.risky_ref(),
        NUMBER.as_bytes(),
        "an FfiValue should seal by value and open to the same text"
    );
}

// --- How many copies each mode makes ----------------------------------------

#[tokio::test]
async fn one_owned_operation_makes_no_copy() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let _: StackCipherText = keyset
        .run(ciphertext::<_, _, Owned>(), value, aead())
        .await
        .unwrap();
    assert_eq!(clones.load(Ordering::SeqCst), 0, "an owned ciphertext");

    let (value, clones) = Counted::new(NUMBER);
    let _: EqualityTerm = keyset
        .run(equality::<_, _, Owned>(), value, caller())
        .await
        .unwrap();
    assert_eq!(clones.load(Ordering::SeqCst), 0, "an owned equality term");
}

/// A ciphertext beside an equality term, as a target composes them.
fn sealed_and_indexed<'s, S, M>(
) -> Encryption<'s, S, (StackCipherText, EqualityTerm), FakeDataKeySource, CallerContext, M>
where
    S: Encrypt + PrfValue + 's,
    M: stack_encrypt::target::ConsumeSource<'s, S> + stack_encrypt::target::ShareSource<'s, S>,
{
    ciphertext().accepting().zip(equality())
}

#[tokio::test]
async fn an_owned_zip_copies_for_every_side_but_the_last() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let (sealed, term) = keyset
        .run(sealed_and_indexed::<_, Owned>(), value, caller())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        1,
        "two owned operations should share one copy: the last takes the value"
    );

    // And what each side made is what it would have made alone.
    let opened: String = cipher.decrypt_as(sealed, aead()).await.unwrap();
    assert_eq!(opened, NUMBER, "the zipped ciphertext opens to the text");
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the zipped term is the text's term");

    let (value, clones) = Counted::new(NUMBER);
    let three = sealed_and_indexed::<_, Owned>().zip(equality::<_, _, Owned>());
    let (_, again) = keyset.run(three, value, caller()).await.unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        2,
        "three owned operations should make two copies"
    );
    assert_eq!(again, expected, "the third side's term is the text's term");
}

#[tokio::test]
async fn a_borrowed_operation_copies_once_for_each_operation_that_consumes() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let sealed: StackCipherText = keyset
        .run(ciphertext::<_, _, Borrowed>(), &value, aead())
        .await
        .unwrap();
    assert_eq!(clones.load(Ordering::SeqCst), 1, "a borrowed ciphertext");
    let opened: String = cipher.decrypt_as(sealed, aead()).await.unwrap();
    assert_eq!(opened, NUMBER, "the borrowed ciphertext opens to the text");

    let (value, clones) = Counted::new(NUMBER);
    let (_, term) = keyset
        .run(sealed_and_indexed::<_, Borrowed>(), &value, caller())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        2,
        "a borrowed ciphertext beside a borrowed term copies once for each"
    );
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the borrowed term is the text's term");
}

#[tokio::test]
async fn a_match_term_never_copies_its_text() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let _: MatchTerm = keyset
        .run(matching::<_, _, Borrowed, _>(), &value, caller())
        .await
        .unwrap();
    let _: MatchTerm = keyset
        .run(matching::<_, _, Owned, _>(), value, caller())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "a match term reads its text in either mode"
    );
}

// --- When an owned plaintext is dropped -------------------------------------

/// A plaintext that counts its drops, so a test can say when an owned value
/// is let go. Its operations take the text out of it, as a zeroizing type
/// would hand its bytes over, and the husk drops at the end of the call.
struct Dropped {
    text: String,
    drops: Arc<AtomicUsize>,
}

impl Dropped {
    fn new(text: &str) -> (Self, Arc<AtomicUsize>) {
        let drops = Arc::new(AtomicUsize::new(0));
        let value = Self {
            text: text.to_string(),
            drops: drops.clone(),
        };
        (value, drops)
    }
}
impl Drop for Dropped {
    fn drop(&mut self) {
        let _ = self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl Encrypt for Dropped {
    fn encrypt_with_aad<'a, C, A>(mut self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        std::mem::take(&mut self.text).encrypt_with_aad(cipher, aad)
    }
}
impl PrfValue for Dropped {
    fn prf_visit_with_context<'a, P, V, C>(
        mut self,
        prf: &P,
        context: C,
        visitor: V,
    ) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        std::mem::take(&mut self.text).prf_visit_with_context(prf, context, visitor)
    }
}
impl AsRef<str> for Dropped {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

/// Owned mode exists so a zeroizing plaintext moves once and is wiped. Each
/// operation must let it go while the description runs, before `run`
/// returns its `Pending` — not keep it alive across the key request.
#[tokio::test]
async fn an_owned_plaintext_is_dropped_before_its_key_request_is_sent() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, drops) = Dropped::new(NUMBER);
    let pending = keyset.run(ciphertext::<_, _, Owned>(), value, aead());
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "ciphertext: dropped before the request is sent"
    );
    let sealed: StackCipherText = pending.await.unwrap();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "ciphertext: dropped exactly once"
    );
    let opened: String = cipher.decrypt_as(sealed, aead()).await.unwrap();
    assert_eq!(
        opened, NUMBER,
        "the text was sealed before the husk dropped"
    );

    let (value, drops) = Dropped::new(NUMBER);
    let pending = keyset.run(equality::<_, _, Owned>(), value, caller());
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "equality: dropped before run returns"
    );
    let term: EqualityTerm = pending.await.unwrap();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "equality: dropped exactly once"
    );
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the term is the text's term");

    let (value, drops) = Dropped::new(NUMBER);
    let pending = keyset.run(matching::<_, _, Owned, _>(), value, caller());
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "matching: dropped before run returns"
    );
    let term: MatchTerm = pending.await.unwrap();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "matching: dropped exactly once"
    );
    let expected: MatchTerm = keyset.match_terms(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the term is the text's term");
}
