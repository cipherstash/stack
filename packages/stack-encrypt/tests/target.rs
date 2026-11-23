//! Target-directed encryption tests, through the owned entry points
//! (`EncryptInto` and `DecryptFrom`): the leaf targets' `EncryptTarget` and
//! `DecryptSource` declarations, a hand-written composite record, a
//! "third-party" term type built on the public extension surface only, and
//! hand-written trees that give a subtree a context of its own. The point of
//! the design is proved here too: however large the assembly, settling it
//! is one batched ZeroKMS call per request kind.

use std::cmp::Ordering;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;

use stack_encrypt::sem::{EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OreTerm};
use stack_encrypt::target::{
    ciphertext, equality, CallerContext, DeclaredContext, DecryptSource, Decryption, EncryptTarget,
    Encryption, NoCallerContext, Pending, Request, RequiredContext,
};
use stack_encrypt::{
    nonempty, DecryptFrom, EmptyError, EncryptInto, Error, NonEmpty, StackCipher, StackCipherText,
};
use stack_kms::{FakeDataKeySource, IdentifiedBy, IndexKeySource};
use uuid::Uuid;
use zeroize::Zeroize;

mod common;
use common::{counting_cipher, stack_cipher};

/// A cipher over the deterministic fake source. Built independently of the
/// test's own [`stack_cipher`]: the fake index key is deterministic per
/// keyset, so two separately built ciphers stand in for the write path and a
/// query path in another process.
async fn generator() -> StackCipher<FakeDataKeySource> {
    stack_cipher().await
}

// --- Leaf implementations ---------------------------------------------------

#[tokio::test]
async fn terms_agree_between_independently_built_ciphers() {
    // Query-side code in another process, holding its own cipher over the same
    // keyset, must produce the same terms
    // as write-side code holding the full StackCipher (same index key).
    let cipher = stack_cipher().await;
    let cipher = cipher.default_keyset();
    let generator = generator().await;
    let generator = generator.default_keyset();

    let a: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, nonempty!("users/email"))
        .await
        .unwrap();
    let b: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(a, b);

    let a: OreTerm<u64> = 7u64
        .encrypt_into_with_context(&cipher, nonempty!("users/n"))
        .await
        .unwrap();
    let b: OreTerm<u64> = 7u64
        .encrypt_into_with_context(&generator, nonempty!("users/n"))
        .await
        .unwrap();
    assert_eq!(a, b);
}

#[tokio::test]
async fn equality_leaf_binds_the_context() {
    let generator = generator().await;
    let generator = generator.default_keyset();

    let email: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/email"))
        .await
        .unwrap();
    let name: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();

    assert_ne!(email, name);
}

#[tokio::test]
async fn term_derivation_makes_no_kms_calls() {
    // Under the local HMAC backend, terms derive under the index key the
    // cipher already holds, so a query probe settles with no ZeroKMS call.
    // That is this backend's property, not the term API's contract: a
    // backend that derives terms at the server (ZeroKMS v2) settles the same
    // `Pending` through a request.
    let (cipher, generates, retrieves) = counting_cipher().await;
    let cipher = cipher.default_keyset();

    let _term: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, nonempty!("users/email"))
        .await
        .unwrap();
    let _ore: OreTerm<u64> = 7u64
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
        .await
        .unwrap();

    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 0);
}

#[tokio::test]
async fn ciphertext_leaf_round_trips_via_decrypt_from() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let ciphertext: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    let plaintext: String =
        String::decrypt_from_with_context(ciphertext, &cipher, nonempty!("users/email"))
            .await
            .unwrap();

    assert_eq!(plaintext, "secret");
}

#[tokio::test]
async fn ciphertext_leaf_cannot_be_transplanted_to_another_context() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let ciphertext: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();

    let transplanted: Result<String, _> =
        String::decrypt_from_with_context(ciphertext, &cipher, nonempty!("users/name")).await;
    assert!(
        transplanted.is_err(),
        "the context is bound into the AAD, so a ciphertext must not decrypt under another field's context"
    );
}

#[tokio::test]
async fn match_leaf_supports_containment_queries() {
    let generator = generator().await;
    let generator = generator.default_keyset();

    let stored: MatchTerms = "alice wonderland"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/bio"))
        .await
        .unwrap();
    let query: MatchTerms = "wonder"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/bio"))
        .await
        .unwrap();

    assert!(stored.contains(&query));
}

/// A match configuration whose options fail the scheme's bounds, so a term
/// under it fails during the synchronous build, before any I/O.
struct TooManyHashes;

impl MatchConfig for TooManyHashes {
    fn options() -> MatchOptions {
        MatchOptions {
            k: 17,
            ..Default::default()
        }
    }
}

/// A custom type-level match configuration.
struct SmallFilter;

impl MatchConfig for SmallFilter {
    fn options() -> MatchOptions {
        MatchOptions {
            m: 64,
            ..Default::default()
        }
    }
}

#[tokio::test]
async fn match_leaf_config_is_type_level() {
    let generator = generator().await;
    let generator = generator.default_keyset();

    let term: MatchTerms<SmallFilter> = "a longer piece of text"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/bio"))
        .await
        .unwrap();
    assert!(term.positions().iter().all(|&p| u32::from(p) < 64));

    // The same text under the default config is a different (larger-filter)
    // term — and a different type, so the two cannot be compared by mistake.
    let default_term: MatchTerms = "a longer piece of text"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/bio"))
        .await
        .unwrap();
    assert_ne!(term.positions(), default_term.positions());
}

#[tokio::test]
async fn ore_leaf_preserves_order_and_binds_the_context() {
    let generator = generator().await;
    let generator = generator.default_keyset();

    let ten: OreTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    let ten_again: OreTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    let twenty: OreTerm<u64> = 20u64
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    let other_field: OreTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, nonempty!("users/height"))
        .await
        .unwrap();

    assert_eq!(ten, ten_again, "ORE terms must be deterministic");
    assert_eq!(ten.cmp(&twenty), Ordering::Less);
    assert_ne!(ten, other_field, "per-context ORE keys must differ");
}

#[tokio::test]
async fn ope_leaf_compares_with_plain_byte_order() {
    use stack_encrypt::sem::OpeTerm;

    let generator = generator().await;
    let generator = generator.default_keyset();

    let ten: OpeTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    let twenty: OpeTerm<u64> = 20u64
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();

    assert_eq!(ten.cmp(&twenty), Ordering::Less);
    assert!(ten.inner().as_ref() < twenty.inner().as_ref());
}

// --- Columns: batching comes from the source shape ---------------------------

#[tokio::test]
async fn a_column_encrypts_in_one_batched_call() {
    let (cipher, generates, _) = counting_cipher().await;
    let cipher = cipher.default_keyset();

    let ages: Vec<u32> = vec![29, 34, 41, 34, 57];
    let sealed: Vec<StackCipherText> = ages
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
        .await
        .unwrap();

    assert_eq!(sealed.len(), 5);
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        1,
        "five records must share ONE generate_keys call"
    );
}

#[tokio::test]
async fn a_column_decrypts_in_one_batched_call() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();

    let ages: Vec<u32> = vec![29, 34, 41];
    let sealed: Vec<StackCipherText> = ages
        .clone()
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .unwrap();

    let roundtrip: Vec<u32> =
        Vec::<u32>::decrypt_from_with_context(sealed, &cipher, nonempty!("users/age"))
            .await
            .unwrap();

    assert_eq!(roundtrip, ages);
    assert_eq!(
        retrieves.load(AtomicOrdering::SeqCst),
        1,
        "three rows must share ONE retrieve_keys call"
    );
}

#[tokio::test]
async fn optional_fields_encrypt_and_decrypt_structurally() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let present: Option<StackCipherText> = Some("here".to_string())
        .encrypt_into_with_context(&keyset, nonempty!("users/nickname"))
        .await
        .unwrap();
    let absent: Option<StackCipherText> = Option::<String>::None
        .encrypt_into_with_context(&keyset, nonempty!("users/nickname"))
        .await
        .unwrap();

    assert!(present.is_some());
    assert!(absent.is_none());

    let roundtrip: Option<String> =
        Option::<String>::decrypt_from_with_context(present, &cipher, nonempty!("users/nickname"))
            .await
            .unwrap();
    assert_eq!(roundtrip.as_deref(), Some("here"));
}

// --- A hand-written composite record ----------------------------------------
//
// The shape a `plaintext = T` derive emits: one declaration, operations
// combined with zip/map (never awaited), one context fanning out to every
// field, the caller seeing a single await — and a single batched call.

/// "An encrypted `u32`, stored as its ciphertext plus an equality term and an
/// ORE term" — an EQL `integer_ord_ore`-shaped record, minus the EQL.
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

impl EncryptTarget<u32> for EncryptedAge {
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, u32, Self, K, Self::ContextInput>
    where
        u32: 's,
    {
        // One context reaches all three; there is no second one to pass.
        // The ciphertext seals under the AEAD half of the one context the
        // terms derive under: `accepting` lets it take theirs. The last
        // `accepting` takes that one context out of the caller's required
        // input.
        stack_encrypt::target::ciphertext()
            .accepting::<CallerContext>()
            .zip(stack_encrypt::target::equality())
            .zip(stack_encrypt::target::ore())
            .map(|((c, hm), ob)| Self { c, hm, ob })
            .accepting()
    }
}
impl DecryptSource<u32> for EncryptedAge {
    type ContextInput = RequiredContext<CallerContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<u32, K> {
        stack_encrypt::target::open(self.c, context.into_inner())
    }
}

#[tokio::test]
async fn composite_record_encrypts_every_field_from_one_source() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = generator().await;
    let generator = generator.default_keyset();

    let record: EncryptedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .unwrap();

    // The ciphertext round-trips through the decrypt mirror.
    let plaintext: u32 = u32::decrypt_from_with_context(record, &cipher, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(plaintext, 42);

    // Each term matches what the primitive would derive on its own, so query
    // terms generated leaf-by-leaf find records encrypted as composites.
    let record: EncryptedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .unwrap();
    let hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(record.hm, hm);

    let ob: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(record.ob, ob);
}

#[tokio::test]
async fn a_composite_record_is_one_batched_call() {
    let (cipher, generates, _) = counting_cipher().await;
    let cipher = cipher.default_keyset();

    let _record: EncryptedAge = 42u32
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        1,
        "ciphertext + two terms must settle in ONE generate_keys call"
    );

    // A whole column of records: still one call.
    let ages: Vec<u32> = vec![10, 20, 30];
    let _column: Vec<EncryptedAge> = ages
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        2,
        "a column of composite records must add ONE more call, not one per row"
    );
}

#[tokio::test]
async fn composite_record_terms_preserve_order() {
    let cipher = stack_cipher().await;
    let cipher = cipher.default_keyset();

    let ten: EncryptedAge = 10u32
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
        .await
        .unwrap();
    let twenty: EncryptedAge = 20u32
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
        .await
        .unwrap();

    assert_eq!(ten.ob.cmp(&twenty.ob), Ordering::Less);
}

// A third-party output can wrap a supported operation, but cannot replace its
// cryptographic implementation. Prefix tokenization would need a core operation.
#[derive(Debug, PartialEq, Eq)]
struct StoredEquality([u8; 32]);
impl<S: Zeroize> EncryptTarget<S> for StoredEquality
where
    EqualityTerm: EncryptTarget<S>,
{
    type ContextInput = <EqualityTerm as EncryptTarget<S>>::ContextInput;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        <EqualityTerm as EncryptTarget<S>>::encryption().map(|term| Self(term.into_bytes()))
    }
}
#[tokio::test]
async fn third_party_output_wraps_a_core_term() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: StoredEquality = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    let canonical: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(
        stored.0,
        canonical.into_bytes(),
        "a hand-written target built on the equality operation matches the term itself"
    );
}

// --- Guard rails --------------------------------------------------------------

#[tokio::test]
async fn init_pins_the_cipher_to_the_keyset_it_resolved() {
    // The keyset a cipher seals data keys under is the same one whose index
    // key derives its terms: `init` resolves both together, so they cannot
    // diverge. (Sealing under one keyset while deriving terms under another
    // would make every query silently match nothing.)
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher");

    let (expected, _) = FakeDataKeySource::new()
        .load_index_key(None)
        .await
        .expect("load index key");
    assert_eq!(cipher.default_keyset().keyset_id().await.unwrap(), expected);
}

#[tokio::test]
async fn an_explicit_keyset_is_honoured() {
    let keyset = Uuid::from_u128(42);
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher");
    let explicit = cipher.keyset(IdentifiedBy::Uuid(keyset));
    assert_eq!(explicit.keyset_id().await.unwrap(), keyset);

    // Selecting one does not move the cipher's default: that is the client's,
    // set by a ZeroKMS administrator, not a preference a caller can override.
    assert_ne!(
        cipher.default_keyset().keyset_id().await.unwrap(),
        keyset,
        "default_keyset() is always the client's default"
    );

    // And its terms differ from the default keyset's: a different keyset means
    // a different index key.
    let default = stack_cipher().await;
    let default = default.default_keyset();
    let a: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&explicit, nonempty!("users/email"))
        .await
        .unwrap();
    let b: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&default, nonempty!("users/email"))
        .await
        .unwrap();
    assert_ne!(a, b, "the keysets' index keys differ");
}

#[test]
fn an_empty_context_cannot_be_built() {
    // The leaves take a `NonEmpty<T>` and nothing else, so an empty context
    // — one that would collapse per-field domain separation — is refused
    // where the value is built, once, by vitaminc's structural check:
    // `""`, `None`, `Some("")`, tuples of empties. There is no runtime path
    // through a leaf for one to fail on, and `nonempty!("")` does not
    // compile.
    assert_eq!(NonEmpty::new("").unwrap_err(), EmptyError);
    assert_eq!(NonEmpty::new(String::new()).unwrap_err(), EmptyError);
    assert_eq!(NonEmpty::new(None::<&str>).unwrap_err(), EmptyError);
    assert_eq!(NonEmpty::new(Some("")).unwrap_err(), EmptyError);
    assert_eq!(NonEmpty::new(("", "")).unwrap_err(), EmptyError);
    // A composite that still carries information is fine — and so is an
    // integer, which is never empty.
    assert!(NonEmpty::new(("", "email")).is_ok());
    assert!(NonEmpty::new(Some("users/email")).is_ok());
    let _: NonEmpty<u64> = 0u64.into();
}

#[tokio::test]
async fn wrapped_and_extended_contexts_bind_like_plain_ones() {
    // vitaminc blanket-implements the context traits for `Option` and
    // tuples, and `NonEmpty::with` extends a proven head with any tail: all
    // of them are contexts a leaf takes, and all of them bind.
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, NonEmpty::new(Some("users/email")).unwrap())
        .await
        .unwrap();
    let opened: String = String::decrypt_from_with_context(
        sealed,
        &cipher,
        NonEmpty::new(Some("users/email")).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(opened, "secret");

    // Extended with a row id: opens under the same pair, and only there.
    // (Against the fake key source the AEAD refuses; ZeroKMS refuses the
    // key retrieval under the other descriptor first, as `Error::Kms`.)
    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email").with(42u64))
        .await
        .unwrap();
    let wrong_row: Result<String, _> =
        String::decrypt_from_with_context(sealed, &cipher, nonempty!("users/email").with(43u64))
            .await;
    assert!(matches!(wrong_row, Err(Error::Aead)));
    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email").with(42u64))
        .await
        .unwrap();
    let no_row: Result<String, _> =
        String::decrypt_from_with_context(sealed, &cipher, nonempty!("users/email")).await;
    assert!(matches!(no_row, Err(Error::Aead)));

    // The pair encodes as the bare tuple would: a term under the extended
    // context equals one under the plain pair, so a query site need not
    // hold a `NonEmpty` head to probe.
    let extended: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email").with(42u64))
        .await
        .unwrap();
    let plain: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, NonEmpty::new(("users/email", 42u64)).unwrap())
        .await
        .unwrap();
    assert_eq!(extended, plain);
    let unextended: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    assert_ne!(extended, unextended);
}

#[tokio::test]
async fn a_bare_integer_is_a_context() {
    // An integer is never empty, so it converts into a `NonEmpty` on its own
    // and the sugar takes it bare.
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, 42u64)
        .await
        .unwrap();
    let opened: String = String::decrypt_from_with_context(sealed, &cipher, NonEmpty::from(42u64))
        .await
        .unwrap();
    assert_eq!(opened, "secret");
    let term: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, 7u32)
        .await
        .unwrap();
    let other: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, 8u32)
        .await
        .unwrap();
    assert_ne!(term, other);
}

#[tokio::test]
async fn containers_pass_the_context_through_to_their_leaves() {
    // `Vec` and `Option` hand the context on untouched, and so hand on the
    // obligation: their context input is the element target's, so a column
    // of leaves requires a context as one leaf does. An empty container
    // derives nothing either way.
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let none: Option<StackCipherText> = None::<String>
        .encrypt_into_with_context(&keyset, nonempty!("users/x"))
        .await
        .unwrap();
    assert!(none.is_none());
    let empty: Vec<StackCipherText> = Vec::<String>::new()
        .encrypt_into_with_context(&keyset, nonempty!("users/x"))
        .await
        .unwrap();
    assert!(empty.is_empty());
    let empty: Vec<String> = Vec::<String>::decrypt_from_with_context(
        Vec::<StackCipherText>::new(),
        &cipher,
        nonempty!("users/x"),
    )
    .await
    .unwrap();
    assert!(empty.is_empty());
}

/// A stored target whose declaration is refused before any key is named —
/// the shape of a derived record whose stored context fails validation.
/// Counts how many times it was asked to declare.
struct Refused(Arc<AtomicUsize>);
impl DecryptSource<u32> for Refused {
    type ContextInput = RequiredContext<CallerContext>;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<u32, K> {
        self.0.fetch_add(1, AtomicOrdering::SeqCst);
        Decryption::failed(Error::NotOpened)
    }
}

#[tokio::test]
async fn a_column_stops_declaring_at_the_first_refused_row() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let declared = Arc::new(AtomicUsize::new(0));
    let column: Vec<Refused> = (0..1_000).map(|_| Refused(Arc::clone(&declared))).collect();

    // `Vec<T>` declares its rows lazily and the collection stops at the
    // first refusal: the rows after it are never asked, and nothing is
    // retrieved.
    let result: Result<Vec<u32>, _> = Vec::<u32>::decrypt_from_with_context(
        column,
        &cipher,
        CallerContext::from(nonempty!("users/age")),
    )
    .await;
    assert!(matches!(result, Err(Error::NotOpened)), "{result:?}");
    assert_eq!(declared.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 0);
}

#[tokio::test]
async fn a_failed_field_fails_the_record_before_any_kms_call() {
    // One failed field must not cause the record's other fields to mint
    // data keys that are then thrown away. A match term under invalid
    // options fails during the synchronous build, before any I/O.
    let (cipher, generates, _) = counting_cipher().await;
    let cipher = cipher.default_keyset();
    let b = "b".to_string();

    let zipped = "abc"
        .to_string()
        .encrypt_into_with_context::<MatchTerms<TooManyHashes>, _>(&cipher, nonempty!("users/x"))
        .zip(
            b.clone()
                .encrypt_into_with_context::<StackCipherText, _>(&cipher, nonempty!("users/x")),
        )
        .await;
    assert!(matches!(zipped, Err(Error::Term(_))));

    let column = Pending::all(
        &cipher,
        vec![
            b.clone()
                .encrypt_into_with_context::<StackCipherText, _>(&cipher, nonempty!("users/x")),
            Pending::failed(&cipher, Error::NotOpened),
        ],
    )
    .await;
    assert!(matches!(column, Err(Error::NotOpened)));

    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        0,
        "a failed sibling must drop the batch, not dispatch it"
    );
}

/// Which `StackCipher` *value* a pending was built through is not part of
/// the merge rule — the keyset is. Two ciphers over the same client config
/// resolve the same default keyset, so their pendings merge and settle as
/// one batch, through the cipher the assembly dispatches on. (Before the
/// multi-keyset `StackCipher` this was pointer equality on the cipher, and
/// refused the pair.)
#[tokio::test]
async fn pendings_from_two_ciphers_over_the_same_keyset_merge() {
    let (cipher_a, generates, _) = counting_cipher().await;
    let cipher_a = cipher_a.default_keyset();
    let cipher_b = counting_cipher().await.0;
    let cipher_b = cipher_b.default_keyset();
    assert_eq!(
        cipher_a.keyset_id().await.unwrap(),
        cipher_b.keyset_id().await.unwrap(),
        "two ciphers over the same client config share a default keyset"
    );
    let v = "v".to_string();
    let w = "w".to_string();

    let zipped = v
        .clone()
        .encrypt_into_with_context::<StackCipherText, _>(&cipher_a, nonempty!("users/x"))
        .zip(
            w.clone()
                .encrypt_into_with_context::<StackCipherText, _>(&cipher_b, nonempty!("users/x")),
        )
        .await;
    assert!(
        zipped.is_ok(),
        "two ciphers over the same keyset must merge: {:?}",
        zipped.err()
    );

    let column = Pending::all(
        &cipher_a,
        vec![
            v.clone()
                .encrypt_into_with_context::<StackCipherText, _>(&cipher_a, nonempty!("users/x")),
            w.clone()
                .encrypt_into_with_context::<StackCipherText, _>(&cipher_b, nonempty!("users/x")),
        ],
    )
    .await;
    assert!(
        column.is_ok(),
        "a column drawn from two ciphers over one keyset must merge: {:?}",
        column.err()
    );

    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        2,
        "each merged assembly settles as exactly one generate_keys call"
    );
}

/// The rule the cipher check gave way to: two *keysets* still refuse to
/// merge, whichever ciphers they came from, and with no I/O.
#[tokio::test]
async fn pendings_from_two_ciphers_over_different_keysets_refuse_to_merge() {
    let (cipher_a, generates, _) = counting_cipher().await;
    let acme = cipher_a.keyset(IdentifiedBy::Name("acme".to_string().into()));
    let cipher_b = counting_cipher().await.0;
    let globex = cipher_b.keyset(IdentifiedBy::Name("globex".to_string().into()));
    let v = "v".to_string();
    let w = "w".to_string();

    let zipped = v
        .clone()
        .encrypt_into_with_context::<StackCipherText, _>(&acme, nonempty!("users/x"))
        .zip(
            w.clone()
                .encrypt_into_with_context::<StackCipherText, _>(&globex, nonempty!("users/x")),
        )
        .await;
    assert!(
        matches!(zipped, Err(Error::KeysetMismatch { left, right })
            if left == acme.keyset_id().await.unwrap() && right == globex.keyset_id().await.unwrap()),
        "expected KeysetMismatch, got: {zipped:?}"
    );

    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        0,
        "a mismatched merge must be refused before any key is minted"
    );
}

#[tokio::test]
async fn an_overdrawing_fulfilment_is_a_response_shape_error() {
    // A fulfilment is scoped to exactly the responses its requests asked for:
    // drawing more must fail loudly, never consume a sibling's responses.
    let cipher = stack_cipher().await;
    let cipher = cipher.default_keyset();

    let pending: Pending<'_, (), _> = Pending::request(
        &cipher,
        vec![Request::generate_data_key(nonempty!("t"))],
        |responses| {
            responses.next_generated_key()?;
            responses.next_generated_key()?; // one more than requested
            Ok(())
        },
    );

    assert!(matches!(pending.await, Err(Error::ResponseShape)));
}

// Terms rebuilt from persisted parts must behave like freshly generated ones.
#[tokio::test]
async fn terms_rehydrate_from_persisted_parts() {
    let generator = generator().await;
    let generator = generator.default_keyset();

    let eq: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/email"))
        .await
        .unwrap();
    let rehydrated = EqualityTerm::from_bytes(eq.clone().into_bytes());
    assert_eq!(eq, rehydrated);

    let stored: MatchTerms = "alice wonderland"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/bio"))
        .await
        .unwrap();
    let query: MatchTerms = "wonder"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/bio"))
        .await
        .unwrap();
    // Rehydrate from unsorted positions: from_positions normalises (and
    // range-checks against the config's filter size).
    let mut positions = stored.clone().into_positions();
    positions.reverse();
    let rehydrated: MatchTerms = MatchTerms::from_positions(positions).unwrap();
    assert_eq!(stored, rehydrated);
    assert!(rehydrated.contains(&query));
}

// The pending futures are `Send` on native targets, so target-directed
// encryption can hop threads (e.g. `tokio::spawn`).
#[tokio::test]
async fn pending_futures_are_send() {
    let generator = generator().await;

    let handle = tokio::spawn(async move {
        let generator = generator.default_keyset();
        let term: EqualityTerm = "alice"
            .to_string()
            .encrypt_into_with_context(&generator, nonempty!("users/email"))
            .await
            .unwrap();
        term
    });

    let _term = handle.await.unwrap();
}

// --- The cipher-directed API is the same path ------------------------------

#[tokio::test]
async fn cipher_directed_encrypt_and_decrypt_are_one_batched_call_each() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();

    let names: Vec<String> = ["ada", "grace", "edsger", "barbara"]
        .into_iter()
        .map(String::from)
        .collect();
    let ct = keyset
        .encrypt_tree(names.clone(), "users/name")
        .await
        .unwrap();
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        1,
        "cipher.encrypt of a four-leaf value must be ONE generate_keys call"
    );

    let roundtrip: Vec<String> = cipher.decrypt(ct, "users/name").await.unwrap();
    assert_eq!(roundtrip, names);
    assert_eq!(
        retrieves.load(AtomicOrdering::SeqCst),
        1,
        "cipher.decrypt of a four-leaf value must be ONE retrieve_keys call"
    );
}

#[tokio::test]
async fn cipher_directed_and_target_directed_ciphertexts_are_interchangeable() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let value = vec!["one".to_string(), "two".to_string(), "three".to_string()];

    // Sealed by the cipher-directed API, opened by the target-directed one.
    let ct = keyset
        .encrypt_tree(value.clone(), "users/tags")
        .await
        .unwrap();
    let via_target: Vec<String> =
        Vec::<String>::decrypt_from_with_context(ct, &cipher, nonempty!("users/tags"))
            .await
            .unwrap();
    assert_eq!(via_target, value);

    // Sealed by the target-directed API, opened by the cipher-directed one.
    let ct: StackCipherText = value
        .clone()
        .encrypt_into_with_context(&keyset, nonempty!("users/tags"))
        .await
        .unwrap();
    let via_cipher: Vec<String> = cipher.decrypt(ct, "users/tags").await.unwrap();
    assert_eq!(via_cipher, value);
}

#[tokio::test]
async fn cipher_directed_decrypt_rejects_a_transplanted_ciphertext() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    let result: Result<String, Error> = cipher.decrypt(ct, "users/name").await;
    assert!(
        matches!(result, Err(Error::Aead)),
        "a target-sealed leaf must not open under another context via the cipher API \
         (the fake key source ignores descriptors; ZeroKMS would refuse the retrieve)"
    );
}

// --- One context per target, threaded through a hand-written tree (ADR-0004)

/// A hand-written composite with a context of its own: the tree is given it
/// once, with `under`, and the caller's context — if any — extends it. The
/// ciphertext and the term beside it are under the same one by
/// construction; there is no second context to hand either.
struct OwnedEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

impl OwnedEmail {
    /// The tree. It runs under a `DeclaredContext`: `()` leaves the tree's
    /// own context as it is, and a context extends it.
    fn tree<'s, K: 'static>() -> Encryption<'s, String, Self, K, DeclaredContext> {
        ciphertext()
            .accepting()
            .zip(equality())
            .under(nonempty!("users/email"))
            .map(|(c, hm)| Self { c, hm })
    }
}

/// As a target, the tree takes no context from its caller: it has its own.
impl EncryptTarget<String> for OwnedEmail {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput>
    where
        String: 's,
    {
        Self::tree().accepting()
    }
}

#[tokio::test]
async fn under_gives_a_subtree_its_own_context_which_the_callers_extends() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = generator().await;
    let generator = generator.default_keyset();
    let email = "alice@example.com".to_string();

    // With no caller context: the own context as it is, for the ciphertext
    // and the term alike.
    let record: OwnedEmail = email.clone().encrypt_into(&keyset).await.unwrap();
    let probe: EqualityTerm = email
        .clone()
        .encrypt_into_with_context(&generator, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(record.hm, probe);
    let opened: String =
        String::decrypt_from_with_context(record.c, &cipher, nonempty!("users/email"))
            .await
            .unwrap();
    assert_eq!(opened, email);

    // Under a caller's context: the own context extended by it, for both.
    // The target takes no caller context, so the tree itself is run.
    let record: OwnedEmail = keyset
        .run(OwnedEmail::tree(), &email, DeclaredContext::from(7u64))
        .await
        .unwrap();
    let probe: EqualityTerm = email
        .clone()
        .encrypt_into_with_context(&generator, nonempty!("users/email").with(7u64))
        .await
        .unwrap();
    assert_eq!(record.hm, probe);
    let opened: String =
        String::decrypt_from_with_context(record.c, &cipher, nonempty!("users/email").with(7u64))
            .await
            .unwrap();
    assert_eq!(opened, email);
}

/// A composite whose ciphertext has a context of its own and whose term is
/// derived under the caller's: `extend` gives the one subtree its own, and
/// the caller's stays required, because the other subtree needs it.
struct ShadowedEmail {
    shadow: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptTarget<String> for ShadowedEmail {
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput>
    where
        String: 's,
    {
        ciphertext()
            .extend::<CallerContext>(nonempty!("users/shadow"))
            .zip(equality())
            .map(|(shadow, hm)| Self { shadow, hm })
            .accepting()
    }
}

#[tokio::test]
async fn extend_gives_a_subtree_its_own_context_and_still_requires_the_callers() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = generator().await;
    let generator = generator.default_keyset();
    let email = "alice@example.com".to_string();

    let record: ShadowedEmail = email
        .clone()
        .encrypt_into_with_context(&keyset, nonempty!("users"))
        .await
        .unwrap();
    // The term is under the caller's context as it is ...
    let probe: EqualityTerm = email
        .clone()
        .encrypt_into_with_context(&generator, nonempty!("users"))
        .await
        .unwrap();
    assert_eq!(record.hm, probe);
    // ... and the ciphertext under its own, extended by the caller's.
    let opened: String = String::decrypt_from_with_context(
        record.shadow,
        &cipher,
        nonempty!("users/shadow").with(nonempty!("users")),
    )
    .await
    .unwrap();
    assert_eq!(opened, email);
}

/// A composite declaring the context its *caller* supplies — a tenant id —
/// while its operations need a `CallerContext`: `accepting` converts once,
/// at the root, and `map_with_context` hands the output what the tree ran
/// under, so the record can keep it.
struct TenantEmail {
    hm: EqualityTerm,
    tenant: u64,
}

impl EncryptTarget<String> for TenantEmail {
    type ContextInput = RequiredContext<NonEmpty<u64>>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput>
    where
        String: 's,
    {
        equality()
            .accepting::<RequiredContext<NonEmpty<u64>>>()
            .map_with_context(|hm, tenant| Self {
                hm,
                tenant: tenant.into_inner().into_inner(),
            })
    }
}

#[tokio::test]
async fn accepting_converts_the_declared_context_once_and_map_with_context_keeps_it() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = generator().await;
    let generator = generator.default_keyset();
    let email = "alice@example.com".to_string();

    let record: TenantEmail = email
        .clone()
        .encrypt_into_with_context(&keyset, NonEmpty::from(7u64))
        .await
        .unwrap();
    assert_eq!(record.tenant, 7);
    let probe: EqualityTerm = email
        .encrypt_into_with_context(&generator, 7u64)
        .await
        .unwrap();
    assert_eq!(record.hm, probe);
}
