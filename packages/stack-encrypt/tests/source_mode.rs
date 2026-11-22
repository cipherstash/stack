//! How a description receives its plaintext (`target::{Borrowed, Owned}`).
//!
//! Every operation reads its plaintext in place, so no mode copies it. A
//! description handed a borrow (the default, and what every
//! `EncryptTarget::encryption` declaration runs in) leaves the value with the
//! caller. One handed the value (`Owned`) reads it and lets go of it. These
//! tests hold the claims that follow:
//!
//! - a plaintext that is **not `Clone`** runs one operation, or several over
//!   the same value, and the output is the same as the borrowed path's;
//! - no operation copies the plaintext, in either mode, alone or beside
//!   others;
//! - an owned plaintext is let go before its key request is sent.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use stack_encrypt::sem::{DefaultMatch, EqualityTerm, MatchTerms};
use stack_encrypt::target::{
    ciphertext, equality, matching, AeadContext, Borrowed, CallerContext, Encrypted, Encryption,
    Owned,
};
use stack_encrypt::target::{EncryptTarget, RequiredContext, StoredContext};
use stack_encrypt::{
    nonempty, DecryptFrom, Encrypt, EncryptInto, Label, NonEmpty, StackCipherText,
};
use stack_kms::FakeDataKeySource;
use vitaminc_aead::plaintext::Sink;
use vitaminc_prf::{IntoPrfContext, Prf, PrfValue, PrfVisitor};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

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
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit(sink)
    }
}
impl Encrypt for &Secret {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self.0).visit(sink)
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
/// Replacing the guard drops the old one, which wipes the text.
impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0 = Protected::new(String::new());
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
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.text.visit(sink)
    }
}
impl Encrypt for &Counted {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self.text).visit(sink)
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
/// The source of an [`EncryptTarget`] must be `Zeroize`. The counter is
/// not secret.
impl Zeroize for Counted {
    fn zeroize(&mut self) {
        self.text.zeroize();
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

    let opened: String = String::decrypt_from_with_context(sealed, &cipher, aead())
        .await
        .unwrap();
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

    let term: MatchTerms = keyset
        .run(matching::<_, _, Owned, _>(), Secret::new(NUMBER), caller())
        .await
        .unwrap();

    let expected: MatchTerms = keyset.match_terms(NUMBER, context()).await.unwrap();
    assert_eq!(
        term, expected,
        "an owned match term should be byte-identical to the same text's term"
    );
}

/// The dynamic value an FFI binding decodes, its frame, is wiped on drop:
/// owned, it seals by value through a ciphertext alone.
#[cfg(feature = "dynamic")]
#[tokio::test]
async fn a_value_frame_seals_by_value_through_ciphertext_alone() {
    use stack_encrypt::dynamic::ValueFrame;

    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let sealed: StackCipherText = keyset
        .run(
            ciphertext::<_, _, Owned>(),
            ValueFrame::of(NUMBER).unwrap(),
            aead(),
        )
        .await
        .unwrap();

    let opened: String = String::decrypt_from_with_context(sealed, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(
        opened, NUMBER,
        "a value frame should seal by value and open to the same text"
    );
}

// --- No mode copies the plaintext --------------------------------------------

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
    S: Encrypt + vitaminc_aead::EncryptRef + Zeroize + 's,
    M: stack_encrypt::target::WipeSource<'s, S>,
{
    ciphertext().accepting().zip(equality())
}

#[tokio::test]
async fn an_owned_zip_makes_no_copy() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let (sealed, term) = keyset
        .run(sealed_and_indexed::<_, Owned>(), value, caller())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "the term reads the value in place, and the ciphertext takes it"
    );

    // And what each side made is what it would have made alone.
    let opened: String = String::decrypt_from_with_context(sealed, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened, NUMBER, "the zipped ciphertext opens to the text");
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the zipped term is the text's term");

    let (value, clones) = Counted::new(NUMBER);
    let three = sealed_and_indexed::<_, Owned>().zip(equality());
    let (_, again) = keyset.run(three, value, caller()).await.unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "three operations over one owned value should make no copy"
    );
    assert_eq!(again, expected, "the third side's term is the text's term");
}

/// A plaintext that is not `Clone` runs a ciphertext and a term over the one
/// value. Before, an owned `zip` needed a copy for every side but the last.
#[tokio::test]
async fn a_plaintext_that_is_not_clone_seals_beside_a_term() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (sealed, term) = keyset
        .run(
            sealed_and_indexed::<_, Owned>(),
            Secret::new(NUMBER),
            caller(),
        )
        .await
        .unwrap();

    let opened: String = String::decrypt_from_with_context(sealed, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened, NUMBER, "the ciphertext opens to the text");
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the term is the text's term");
}

#[tokio::test]
async fn a_borrowed_operation_makes_no_copy() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let sealed: StackCipherText = keyset
        .run(ciphertext::<_, _, Borrowed>(), &value, aead())
        .await
        .unwrap();
    assert_eq!(clones.load(Ordering::SeqCst), 0, "a borrowed ciphertext");
    let opened: String = String::decrypt_from_with_context(sealed, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened, NUMBER, "the borrowed ciphertext opens to the text");

    let (value, clones) = Counted::new(NUMBER);
    let (_, term) = keyset
        .run(sealed_and_indexed::<_, Borrowed>(), &value, caller())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "a borrowed ciphertext beside a borrowed term reads the one value"
    );
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the borrowed term is the text's term");
}

#[tokio::test]
async fn a_match_term_never_copies_its_text() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let _: MatchTerms = keyset
        .run(matching::<_, _, Borrowed, _>(), &value, caller())
        .await
        .unwrap();
    let _: MatchTerms = keyset
        .run(matching::<_, _, Owned, _>(), value, caller())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "a match term reads its text in either mode"
    );
}

// --- How many copies a derived `plaintext = T` record makes ----------------

/// A record with one field derived from the plaintext: its owned form moves
/// the value into that field's owned form.
#[derive(EncryptTarget)]
#[stash(plaintext = Counted)]
struct SealedOnly {
    c: StackCipherText,
}

/// The same, storing the context it was sealed under.
#[derive(EncryptTarget)]
#[stash(plaintext = Counted)]
struct SealedWithContext {
    #[stash(context_field)]
    scope: Label,
    c: StackCipherText,
}

/// A record with two fields derived from the plaintext: its owned form is the
/// default, which reads the value through the borrowed form. Both fields read
/// the value in place.
#[derive(EncryptTarget)]
#[stash(plaintext = Counted)]
struct SealedAndEqual {
    c: StackCipherText,
    hm: EqualityTerm,
}

fn scope() -> NonEmpty<Label> {
    NonEmpty::from(Label::parse("cards/number").unwrap())
}

#[tokio::test]
async fn a_record_with_one_derived_field_moves_the_value_into_it() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let owned: SealedOnly = value
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "the owned form copies nothing"
    );
    let opened: String = String::decrypt_from_with_context(owned.c, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened, NUMBER, "the moved value is what is sealed");

    // The borrowed form, which a collection runs for each element, reads
    // the value in place.
    let (value, clones) = Counted::new(NUMBER);
    let _: SealedOnly = keyset
        .run(
            <SealedOnly as EncryptTarget<Counted>>::encryption(),
            &value,
            RequiredContext::from(caller()),
        )
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "the borrowed form reads the value in place"
    );

    // A record that stores its context moves the value too.
    let (value, clones) = Counted::new(NUMBER);
    let stored: SealedWithContext = value
        .encrypt_into_with_context(&keyset, scope())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "the owned form copies nothing"
    );
    assert_eq!(stored.scope, scope().into_inner());
    let opened: String =
        String::decrypt_from_with_context(stored.c, &cipher, AeadContext::from(scope()))
            .await
            .unwrap();
    assert_eq!(opened, NUMBER, "the moved value is what is sealed");
    let (value, clones) = Counted::new(NUMBER);
    let _: SealedWithContext = keyset
        .run(
            <SealedWithContext as EncryptTarget<Counted>>::encryption(),
            &value,
            StoredContext::from(scope()),
        )
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "the borrowed form reads the value in place"
    );
}

#[tokio::test]
async fn a_record_with_two_derived_fields_copies_nothing() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, clones) = Counted::new(NUMBER);
    let record: SealedAndEqual = value
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(
        clones.load(Ordering::SeqCst),
        0,
        "both fields read the value in place"
    );
    let opened: String = String::decrypt_from_with_context(record.c, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened, NUMBER);
    let expected = keyset.equality_term(NUMBER, context()).await.unwrap();
    assert_eq!(record.hm, expected);
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
    fn visit<S: Sink>(mut self, sink: S) -> Result<S::Ok, S::Error> {
        std::mem::take(&mut self.text).visit(sink)
    }
}
impl Encrypt for &Dropped {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self.text).visit(sink)
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
impl Zeroize for Dropped {
    fn zeroize(&mut self) {
        self.text.zeroize();
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
    let opened: String = String::decrypt_from_with_context(sealed, &cipher, aead())
        .await
        .unwrap();
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
    let term: MatchTerms = pending.await.unwrap();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "matching: dropped exactly once"
    );
    let expected: MatchTerms = keyset.match_terms(NUMBER, context()).await.unwrap();
    assert_eq!(term, expected, "the term is the text's term");
}

// --- An owned value is wiped once ---------------------------------------------

/// A plaintext that counts its wipes, and is not `Clone`. Walked by value,
/// it reads its text and then wipes itself, as a Vitamin C type does. So a
/// wipe is counted whether the value was sealed or let go unread.
struct Wiped {
    text: String,
    wipes: Arc<AtomicUsize>,
}

impl Wiped {
    fn new(text: &str) -> (Self, Arc<AtomicUsize>) {
        let wipes = Arc::new(AtomicUsize::new(0));
        let value = Self {
            text: text.to_string(),
            wipes: wipes.clone(),
        };
        (value, wipes)
    }
}
impl Zeroize for Wiped {
    fn zeroize(&mut self) {
        let _ = self.wipes.fetch_add(1, Ordering::SeqCst);
        self.text.zeroize();
    }
}
impl Encrypt for Wiped {
    fn visit<S: Sink>(mut self, sink: S) -> Result<S::Ok, S::Error> {
        let walked = self.text.as_str().visit(sink);
        self.zeroize();
        walked
    }
}
impl Encrypt for &Wiped {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.text.as_str().visit(sink)
    }
}
impl AsRef<str> for Wiped {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

/// A ciphertext and two terms over one value.
type SealedEqualAndMatched = Encrypted<(EqualityTerm, MatchTerms)>;

fn an_empty_scope() -> RequiredContext<CallerContext> {
    RequiredContext::from(CallerContext::from(stack_encrypt::target::Scope::new(
        String::new(),
    )))
}

/// `encrypt_into` hands the value to the one operation written first. The
/// two terms read it in place, the ciphertext seals it, and the value is
/// wiped once. A refused context wipes it once too, and seals nothing.
#[tokio::test]
async fn a_value_with_a_ciphertext_and_two_terms_is_wiped_once() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, wipes) = Wiped::new(NUMBER);
    let sealed: SealedEqualAndMatched = value
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(wipes.load(Ordering::SeqCst), 1, "sealed: one wipe");
    let opened: String = String::decrypt_from_with_context(sealed.ciphertext, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened, NUMBER);
    let (equal, matched) = sealed.terms;
    assert_eq!(
        equal,
        keyset.equality_term(NUMBER, context()).await.unwrap()
    );
    let expected: MatchTerms = keyset.match_terms(NUMBER, context()).await.unwrap();
    assert_eq!(matched, expected);

    let (value, wipes) = Wiped::new(NUMBER);
    let refused = keyset
        .run(
            <SealedEqualAndMatched as EncryptTarget<Wiped>>::owned_encryption(),
            value,
            an_empty_scope(),
        )
        .await;
    assert!(refused.is_err(), "an empty scope is refused");
    assert_eq!(wipes.load(Ordering::SeqCst), 1, "refused: one wipe");

    // The borrowed form leaves the value with the caller.
    let (value, wipes) = Wiped::new(NUMBER);
    let _: SealedEqualAndMatched = keyset
        .run(
            <SealedEqualAndMatched as EncryptTarget<Wiped>>::encryption(),
            &value,
            RequiredContext::from(caller()),
        )
        .await
        .unwrap();
    assert_eq!(wipes.load(Ordering::SeqCst), 0, "borrowed: the caller's");
    drop(value);
}

/// Each public operation, composed by hand in `Owned` mode, wipes the value
/// it is handed once: after it is read, and when the context is refused.
#[tokio::test]
async fn each_owned_operation_wipes_its_value_once() {
    use stack_encrypt::target::Scope;
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let empty = || CallerContext::from(Scope::new(String::new()));

    macro_rules! wiped_once {
        ($operation:expr, $context:expr, $what:literal) => {{
            let (value, wipes) = Wiped::new(NUMBER);
            let _ = keyset.run($operation, value, $context).await;
            assert_eq!(wipes.load(Ordering::SeqCst), 1, $what);
        }};
    }
    wiped_once!(ciphertext::<_, _, Owned>(), aead(), "ciphertext, sealed");
    wiped_once!(
        ciphertext::<_, _, Owned>(),
        AeadContext::from(Scope::new(String::new())),
        "ciphertext, refused"
    );
    wiped_once!(equality::<_, _, Owned>(), caller(), "equality, derived");
    wiped_once!(equality::<_, _, Owned>(), empty(), "equality, refused");
    wiped_once!(
        matching::<_, _, Owned, DefaultMatch>(),
        caller(),
        "matching, derived"
    );
    wiped_once!(
        matching::<_, _, Owned, DefaultMatch>(),
        empty(),
        "matching, refused"
    );
}

// --- An owned value is wiped when a reader panics ------------------------------

/// A plaintext that cannot be read in place: `as_ref` and the by-reference
/// `Encrypt` panic. It counts its wipes, as [`Wiped`] does, and seals by
/// value.
struct Exploding {
    text: String,
    wipes: Arc<AtomicUsize>,
}

impl Exploding {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let wipes = Arc::new(AtomicUsize::new(0));
        let value = Self {
            text: NUMBER.to_string(),
            wipes: wipes.clone(),
        };
        (value, wipes)
    }
}
impl Zeroize for Exploding {
    fn zeroize(&mut self) {
        let _ = self.wipes.fetch_add(1, Ordering::SeqCst);
        self.text.zeroize();
    }
}
impl Encrypt for Exploding {
    fn visit<S: Sink>(mut self, sink: S) -> Result<S::Ok, S::Error> {
        let walked = self.text.as_str().visit(sink);
        self.zeroize();
        walked
    }
}
impl Encrypt for &Exploding {
    fn visit<S: Sink>(self, _: S) -> Result<S::Ok, S::Error> {
        panic!("the value cannot be read in place")
    }
}
impl AsRef<str> for Exploding {
    fn as_ref(&self) -> &str {
        panic!("the text cannot be read")
    }
}

/// An owned value that a borrowed reader in `zip` panics over is wiped
/// once, as the stack unwinds, and so is one that a match term panics over
/// alone.
#[tokio::test]
async fn an_owned_value_is_wiped_once_when_a_reader_panics() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (value, wipes) = Exploding::new();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let sealed_and_matched = ciphertext::<_, _, Owned>()
            .accepting::<CallerContext>()
            .zip(matching::<_, _, Borrowed, DefaultMatch>());
        drop(keyset.run(sealed_and_matched, value, caller()));
    }));
    assert!(unwound.is_err(), "the reader panicked");
    assert_eq!(wipes.load(Ordering::SeqCst), 1, "zip: one wipe");

    let (value, wipes) = Exploding::new();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        drop(keyset.run(matching::<_, _, Owned, DefaultMatch>(), value, caller()));
    }));
    assert!(unwound.is_err(), "the match term panicked");
    assert_eq!(wipes.load(Ordering::SeqCst), 1, "matching: one wipe");

    // A target's equality term reads the value by reference beside the
    // ciphertext that takes it.
    let (value, wipes) = Exploding::new();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let indexed = stack_encrypt::target::indexed::<_, _, Owned, _>(stack_encrypt::Equality);
        drop(keyset.run(indexed, value, caller()));
    }));
    assert!(unwound.is_err(), "the equality term panicked");
    assert_eq!(wipes.load(Ordering::SeqCst), 1, "indexed: one wipe");
}

// --- A query value is wiped when its context is refused ------------------------

/// A record whose one field is a [`Wiped`], so a query of it counts wipes.
#[derive(Zeroize)]
struct Card {
    number: Wiped,
}

/// A query takes a `Wiped` as it is, as it takes a `String`.
impl stack_encrypt::field_reference::QueryInput for Wiped {
    type Value = Wiped;
    fn into_value(self) -> Wiped {
        self
    }
}

#[derive(EncryptTarget)]
#[stash(struct = Card, scope = "cards", scope(region: String))]
#[allow(dead_code)]
struct EncryptedCard {
    number: Encrypted<EqualityTerm>,
}

/// A typed query hands its value to the index by value. A scope with an
/// empty part is refused, and the value is wiped once.
#[tokio::test]
async fn a_query_value_refused_for_its_scope_is_wiped_once() {
    use stack_encrypt::target::Scope;
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let (value, wipes) = Wiped::new(NUMBER);
    let refused = EncryptedCard::NUMBER
        .eq(value)
        .scope(Scope::new(String::new()))
        .encrypt(&keyset)
        .await;
    assert!(refused.is_err(), "an empty scope is refused");
    assert_eq!(wipes.load(Ordering::SeqCst), 1, "one wipe");
}

// --- A date with a ciphertext and several terms ------------------------------

/// A date is not `Clone`, so sealing it with a ciphertext, an equality term
/// and an order term cannot copy it. The owned form gives the same terms
/// as the borrowed form, and the ciphertext opens to the date.
#[cfg(feature = "jiff")]
#[tokio::test]
async fn a_date_with_a_ciphertext_and_two_terms_is_not_copied() {
    use stack_encrypt::sem::{OreBlockTerm, OreTerm};
    use stack_encrypt::value::Date;
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let date = || Date::new(jiff::civil::date(2024, 2, 29));

    let sealed: Encrypted<(EqualityTerm, OreTerm<Date>)> = date()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let borrowed: Encrypted<(EqualityTerm, OreTerm<Date>)> = keyset
        .run(
            <Encrypted<(EqualityTerm, OreTerm<Date>)> as EncryptTarget<Date>>::encryption(),
            &date(),
            RequiredContext::from(caller()),
        )
        .await
        .unwrap();
    assert_eq!(sealed.terms.0, borrowed.terms.0, "the equality term");
    assert_eq!(sealed.terms.1, borrowed.terms.1, "the order term");
    let opened = Date::decrypt_from_with_context(sealed.ciphertext, &cipher, aead())
        .await
        .unwrap();
    assert_eq!(opened.to_jiff(), date().to_jiff());

    // Block ORE, the scheme EQL v4 stores, the same way.
    let sealed: Encrypted<(EqualityTerm, OreBlockTerm<Date>)> = date()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let later = keyset
        .ore_block_term(Date::new(jiff::civil::date(2024, 3, 1)), context())
        .await
        .unwrap();
    assert_eq!(
        sealed.terms.1.compare(&later),
        Some(std::cmp::Ordering::Less),
        "the term orders as the date"
    );
}
