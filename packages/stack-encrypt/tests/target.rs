//! Target-directed encryption tests: leaf `EncryptFrom`/`DecryptInto`
//! implementations, a hand-written composite record (the shape a future
//! derive will emit), a "third-party" term type built on the public extension
//! surface only, and — the point of the design — proof that however large the
//! assembly, settling it is one batched ZeroKMS call per request kind.

use std::cmp::Ordering;
use std::sync::atomic::Ordering as AtomicOrdering;

use stack_encrypt::sem::{EqualityTerm, MatchConfig, MatchOptions, MatchTerm, OreTerm};
use stack_encrypt::target::{
    is_degenerate_prf_context, DecryptInto, EncryptContext, EncryptFrom, EncryptInto, Pending,
    Request, SuppliedContext,
};
use stack_encrypt::{Error, StackCipher, StackCipherText};
use stack_kms::{FakeDataKeySource, IdentifiedBy, IndexKeySource};
use uuid::Uuid;
use vitaminc_prf::{BlockVisitor, PrfContext, PrfValue};

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
async fn equality_leaf_agrees_with_the_descriptor_api() {
    let generator = generator().await;

    let via_target: EqualityTerm = "alice"
        .encrypt_into_with_context(&generator, "users/email")
        .await
        .unwrap();
    let via_descriptor = generator
        .equality_term("alice", "users/email")
        .await
        .unwrap();

    assert_eq!(
        via_target, via_descriptor,
        "target-directed and descriptor-string call sites must agree on term bytes"
    );
}

#[tokio::test]
async fn terms_agree_between_independently_built_ciphers() {
    // Query-side code in another process, holding its own cipher over the same
    // keyset, must produce the same terms
    // as write-side code holding the full StackCipher (same index key).
    let cipher = stack_cipher().await;
    let generator = generator().await;

    let a: EqualityTerm = "alice"
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();
    let b: EqualityTerm = "alice"
        .encrypt_into_with_context(&generator, "users/email")
        .await
        .unwrap();
    assert_eq!(a, b);

    let a: OreTerm<u64> = 7u64
        .encrypt_into_with_context(&cipher, "users/n")
        .await
        .unwrap();
    let b: OreTerm<u64> = 7u64
        .encrypt_into_with_context(&generator, "users/n")
        .await
        .unwrap();
    assert_eq!(a, b);
}

#[tokio::test]
async fn equality_leaf_binds_the_context() {
    let generator = generator().await;

    let email: EqualityTerm = "alice"
        .encrypt_into_with_context(&generator, "users/email")
        .await
        .unwrap();
    let name: EqualityTerm = "alice"
        .encrypt_into_with_context(&generator, "users/name")
        .await
        .unwrap();

    assert_ne!(email, name);
}

#[tokio::test]
async fn term_derivation_makes_no_kms_calls() {
    // Terms derive under the index key the cipher already holds: building a
    // query probe must never touch ZeroKMS.
    let (cipher, generates, retrieves) = counting_cipher().await;

    let _term: EqualityTerm = "alice"
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();
    let _ore: OreTerm<u64> = 7u64
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();

    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 0);
}

#[tokio::test]
async fn ciphertext_leaf_round_trips_via_decrypt_into() {
    let cipher = stack_cipher().await;

    let ciphertext: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();
    let plaintext: String = ciphertext
        .decrypt_into(&cipher, "users/email")
        .await
        .unwrap();

    assert_eq!(plaintext, "secret");
}

#[tokio::test]
async fn ciphertext_leaf_cannot_be_transplanted_to_another_context() {
    let cipher = stack_cipher().await;

    let ciphertext: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();

    let transplanted: Result<String, _> = ciphertext.decrypt_into(&cipher, "users/name").await;
    assert!(
        transplanted.is_err(),
        "the context is bound into the AAD, so a ciphertext must not decrypt under another field's context"
    );
}

#[tokio::test]
async fn match_leaf_supports_containment_queries() {
    let generator = generator().await;

    let stored: MatchTerm = "alice wonderland"
        .to_string()
        .encrypt_into_with_context(&generator, "users/bio")
        .await
        .unwrap();
    let query: MatchTerm = "wonder"
        .to_string()
        .encrypt_into_with_context(&generator, "users/bio")
        .await
        .unwrap();

    assert!(stored.contains(&query));
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

    let term: MatchTerm<SmallFilter> = "a longer piece of text"
        .to_string()
        .encrypt_into_with_context(&generator, "users/bio")
        .await
        .unwrap();
    assert!(term.positions().iter().all(|&p| u32::from(p) < 64));

    // The same text under the default config is a different (larger-filter)
    // term — and a different type, so the two cannot be compared by mistake.
    let default_term: MatchTerm = "a longer piece of text"
        .to_string()
        .encrypt_into_with_context(&generator, "users/bio")
        .await
        .unwrap();
    assert_ne!(term.positions(), default_term.positions());
}

#[tokio::test]
async fn ore_leaf_preserves_order_and_binds_the_context() {
    let generator = generator().await;

    let ten: OreTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    let ten_again: OreTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    let twenty: OreTerm<u64> = 20u64
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    let other_field: OreTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, "users/height")
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

    let ten: OpeTerm<u64> = 10u64
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    let twenty: OpeTerm<u64> = 20u64
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();

    assert_eq!(ten.cmp(&twenty), Ordering::Less);
    assert!(ten.inner().as_ref() < twenty.inner().as_ref());
}

// --- Columns: batching comes from the source shape ---------------------------

#[tokio::test]
async fn a_column_encrypts_in_one_batched_call() {
    let (cipher, generates, _) = counting_cipher().await;

    let ages: Vec<u32> = vec![29, 34, 41, 34, 57];
    let sealed: Vec<StackCipherText> = ages
        .encrypt_into_with_context(&cipher, "users/age")
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

    let ages: Vec<u32> = vec![29, 34, 41];
    let sealed: Vec<StackCipherText> = ages
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();

    let roundtrip: Vec<u32> = sealed.decrypt_into(&cipher, "users/age").await.unwrap();

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

    let present: Option<StackCipherText> = Some("here".to_string())
        .encrypt_into_with_context(&cipher, "users/nickname")
        .await
        .unwrap();
    let absent: Option<StackCipherText> = Option::<String>::None
        .encrypt_into_with_context(&cipher, "users/nickname")
        .await
        .unwrap();

    assert!(present.is_some());
    assert!(absent.is_none());

    let roundtrip: Option<String> = present
        .decrypt_into(&cipher, "users/nickname")
        .await
        .unwrap();
    assert_eq!(roundtrip.as_deref(), Some("here"));
}

// --- A hand-written composite record ----------------------------------------
//
// The shape a `#[derive(EncryptFrom)]` will emit: one impl, pendings combined
// with zip/map (never awaited), one context fanning out to every field, the
// caller seeing a single await — and a single batched call.

/// "An encrypted `u32`, stored as its ciphertext plus an equality term and an
/// ORE term" — an EQL `integer_ord_ore`-shaped record, minus the EQL.
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

// The record hands the caller's context to its leaves, so it needs what
// they need — inherited through per-field bounds, the same clauses the
// derive emits, rather than restated as a leaf-policy bound of the record's
// own (which would need editing every time the leaves' policy tightens).
impl<K, Ctx> EncryptFrom<u32, StackCipher<K>, Ctx> for EncryptedAge
where
    Ctx: Clone,
    StackCipherText: EncryptFrom<u32, StackCipher<K>, Ctx>,
    EqualityTerm: EncryptFrom<u32, StackCipher<K>, Ctx>,
    OreTerm<u32>: EncryptFrom<u32, StackCipher<K>, Ctx>,
{
    fn encrypt_from<'a>(
        source: &'a u32,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        StackCipherText::encrypt_from(source, cipher, context.clone())
            .zip(EqualityTerm::encrypt_from(source, cipher, context.clone()))
            .zip(OreTerm::<u32>::encrypt_from(source, cipher, context))
            .map(|((c, hm), ob)| Self { c, hm, ob })
    }
}

/// The decrypt mirror a derive would emit: only the ciphertext field
/// participates — terms are one-way — and its context demand is inherited
/// through the field bound, as on the encrypt side.
impl<K, Ctx> DecryptInto<u32, StackCipher<K>, Ctx> for EncryptedAge
where
    StackCipherText: DecryptInto<u32, StackCipher<K>, Ctx>,
{
    fn decrypt_into<'a>(self, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, u32, K>
    where
        Self: 'a,
        u32: 'a,
    {
        self.c.decrypt_into(cipher, context)
    }
}

#[tokio::test]
async fn composite_record_encrypts_every_field_from_one_source() {
    let cipher = stack_cipher().await;
    let generator = generator().await;

    let record: EncryptedAge = 42u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();

    // The ciphertext round-trips through the decrypt mirror.
    let plaintext: u32 = record.decrypt_into(&cipher, "users/age").await.unwrap();
    assert_eq!(plaintext, 42);

    // Each term matches what the primitive would derive on its own, so query
    // terms generated leaf-by-leaf find records encrypted as composites.
    let record: EncryptedAge = 42u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();
    let hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    assert_eq!(record.hm, hm);

    let ob: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    assert_eq!(record.ob, ob);
}

#[tokio::test]
async fn a_composite_record_is_one_batched_call() {
    let (cipher, generates, _) = counting_cipher().await;

    let _record: EncryptedAge = 42u32
        .encrypt_into_with_context(&cipher, "users/age")
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
        .encrypt_into_with_context(&cipher, "users/age")
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

    let ten: EncryptedAge = 10u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();
    let twenty: EncryptedAge = 20u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();

    assert_eq!(ten.ob.cmp(&twenty.ob), Ordering::Less);
}

// --- A "third-party" term type ----------------------------------------------
//
// Defined here using only the public extension surface: `EncryptFrom`,
// `Pending::ready`, and the cipher's public PRF. This is the proof that the
// set of SEM types is open — a separate crate can do exactly this.

/// A prefix term: the PRF of the first `N` characters of a string, enabling
/// "starts with" queries on the first N chars. (Illustrative only.)
#[derive(Debug, PartialEq, Eq)]
struct PrefixTerm<const N: usize>([u8; 32]);

impl<'c, S, K, Ctx, const N: usize> EncryptFrom<S, StackCipher<K>, Ctx> for PrefixTerm<N>
where
    S: AsRef<str>,
    Ctx: EncryptContext<'c> + SuppliedContext<'c>,
{
    fn encrypt_from<'a>(
        source: &'a S,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        // The same non-emptiness check the built-in leaves make, then an own
        // domain label: can never collide with a built-in term under the
        // same context.
        let context = context.into_prf_context().into_owned();
        if is_degenerate_prf_context(context.as_bytes()) {
            return Pending::ready(cipher, Err(Error::EmptyContext));
        }
        let context = PrfContext::pae(&[
            b"example/prefix-term/v1",
            &(N as u64).to_le_bytes(),
            context.as_bytes(),
        ]);
        let prefix: String = source.as_ref().chars().take(N).collect();
        let term = prefix
            .prf_visit_with_context(cipher.prf().clone(), context, BlockVisitor)
            .into_result()
            .map(PrefixTerm)
            .map_err(|e| Error::Other(Box::new(e)));
        Pending::ready(cipher, term)
    }
}

#[tokio::test]
async fn third_party_term_type_works_on_the_public_surface() {
    let cipher = stack_cipher().await;
    let generator = generator().await;

    let stored: PrefixTerm<3> = "alice"
        .encrypt_into_with_context(&cipher, "users/name")
        .await
        .unwrap();
    let probe: PrefixTerm<3> = "alicia"
        .encrypt_into_with_context(&generator, "users/name")
        .await
        .unwrap();
    let miss: PrefixTerm<3> = "bob"
        .encrypt_into_with_context(&generator, "users/name")
        .await
        .unwrap();

    assert_eq!(stored, probe, "same 3-char prefix, same term");
    assert_ne!(stored, miss);

    // And it composes into a record like any built-in term.
    struct NameRecord {
        c: StackCipherText,
        prefix: PrefixTerm<3>,
    }

    impl<'c, K, Ctx> EncryptFrom<String, StackCipher<K>, Ctx> for NameRecord
    where
        Ctx: EncryptContext<'c> + SuppliedContext<'c>,
    {
        fn encrypt_from<'a>(
            source: &'a String,
            cipher: &'a StackCipher<K>,
            context: Ctx,
        ) -> Pending<'a, Self, K>
        where
            Self: 'a,
        {
            StackCipherText::encrypt_from(source, cipher, context.clone())
                .zip(PrefixTerm::<3>::encrypt_from(source, cipher, context))
                .map(|(c, prefix)| Self { c, prefix })
        }
    }

    let record: NameRecord = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/name")
        .await
        .unwrap();
    assert_eq!(record.prefix, stored);
    let name: String = record.c.decrypt_into(&cipher, "users/name").await.unwrap();
    assert_eq!(name, "alice");
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
    assert_eq!(cipher.keyset_id(), expected);
}

#[tokio::test]
async fn an_explicit_keyset_is_honoured() {
    let keyset = Uuid::from_u128(42);
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .keyset(IdentifiedBy::Uuid(keyset))
        .init()
        .await
        .expect("build cipher");

    assert_eq!(cipher.keyset_id(), keyset);

    // And its terms differ from the default keyset's: a different keyset means
    // a different index key.
    let default = stack_cipher().await;
    let a = cipher.equality_term("alice", "users/email").await.unwrap();
    let b = default.equality_term("alice", "users/email").await.unwrap();
    assert_ne!(a, b);
}

#[tokio::test]
async fn empty_context_is_rejected_everywhere() {
    use stack_encrypt::sem::{OpeTerm, TermError};

    let cipher = stack_cipher().await;
    let generator = generator().await;

    // Terms: an empty context would collapse per-field domain separation.
    // Rejected during the synchronous build — before any I/O could happen.
    let eq: Result<EqualityTerm, _> = "alice".encrypt_into_with_context(&generator, "").await;
    assert!(matches!(eq, Err(Error::EmptyContext)));
    let m: Result<MatchTerm, _> = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, "")
        .await;
    assert!(matches!(m, Err(Error::EmptyContext)));
    let ore: Result<OreTerm<u64>, _> = 7u64.encrypt_into_with_context(&generator, "").await;
    assert!(matches!(ore, Err(Error::EmptyContext)));
    let ope: Result<OpeTerm<u64>, _> = 7u64.encrypt_into_with_context(&generator, "").await;
    assert!(matches!(ope, Err(Error::EmptyContext)));

    // Descriptor-string convenience methods route through the same guard.
    assert!(matches!(
        generator.equality_term("alice", "").await,
        Err(TermError::EmptyContext)
    ));

    // The ciphertext leaf: an empty AAD would make ciphertexts transplantable
    // between ()-context fields.
    let ct: Result<StackCipherText, _> = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, "")
        .await;
    assert!(matches!(ct, Err(Error::EmptyContext)));

    // And the decrypt mirror never opens under one either.
    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();
    let opened: Result<String, _> = sealed.decrypt_into(&cipher, "").await;
    assert!(matches!(opened, Err(Error::EmptyContext)));
}

#[tokio::test]
async fn wrapped_empty_contexts_are_rejected_too() {
    // vitaminc blanket-implements the context traits for `Option` and tuples,
    // whose encodings of "nothing" are non-empty byte strings. The guard is
    // structural, so none of these get through on any path.
    let cipher = stack_cipher().await;

    let eq: Result<EqualityTerm, _> = "alice"
        .encrypt_into_with_context(&cipher, None::<&str>)
        .await;
    assert!(matches!(eq, Err(Error::EmptyContext)));
    let eq: Result<EqualityTerm, _> = "alice".encrypt_into_with_context(&cipher, Some("")).await;
    assert!(matches!(eq, Err(Error::EmptyContext)));
    let eq: Result<EqualityTerm, _> = "alice".encrypt_into_with_context(&cipher, ("", "")).await;
    assert!(matches!(eq, Err(Error::EmptyContext)));

    let ore: Result<OreTerm<u64>, _> = 7u64.encrypt_into_with_context(&cipher, None::<&str>).await;
    assert!(matches!(ore, Err(Error::EmptyContext)));

    let ct: Result<StackCipherText, _> = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, None::<&str>)
        .await;
    assert!(matches!(ct, Err(Error::EmptyContext)));

    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();
    let opened: Result<String, _> = sealed.decrypt_into(&cipher, None::<&str>).await;
    assert!(matches!(opened, Err(Error::EmptyContext)));

    // A wrapped context that does carry information still works, and binds.
    let sealed: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, Some("users/email"))
        .await
        .unwrap();
    let opened: String = sealed
        .decrypt_into(&cipher, Some("users/email"))
        .await
        .unwrap();
    assert_eq!(opened, "secret");
}

#[tokio::test]
async fn containers_pass_the_context_through_to_their_leaves() {
    // `Vec` and `Option` validate nothing themselves: a populated container
    // under an empty context fails at the first leaf (synchronously, before
    // any I/O), and an empty one has no leaf to fail at. Whether a context
    // is *owed* at all is likewise the leaves' call, passed through the
    // type: a column of leaves is `EncryptFrom<_, _, Ctx>` only for a
    // supplied `Ctx` (`tests/ui/leaf_without_context.rs`), a column of
    // derived rows — records whose fields carry their own contexts — for
    // any, so it is encrypted with no context at all.
    let (cipher, generates, _) = counting_cipher().await;

    let some: Result<Option<StackCipherText>, _> = Some("x".to_string())
        .encrypt_into_with_context(&cipher, "")
        .await;
    assert!(matches!(some, Err(Error::EmptyContext)));
    let populated: Result<Vec<StackCipherText>, _> = vec!["x".to_string()]
        .encrypt_into_with_context(&cipher, "")
        .await;
    assert!(matches!(populated, Err(Error::EmptyContext)));
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);

    let none: Option<StackCipherText> = None::<String>
        .encrypt_into_with_context(&cipher, "users/x")
        .await
        .unwrap();
    assert!(none.is_none());
    let empty: Vec<StackCipherText> = Vec::<String>::new()
        .encrypt_into_with_context(&cipher, "users/x")
        .await
        .unwrap();
    assert!(empty.is_empty());
    let empty: Vec<String> = Vec::<StackCipherText>::new()
        .decrypt_into(&cipher, "users/x")
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn a_failed_field_fails_the_record_before_any_kms_call() {
    // One misconfigured field must not cause the record's other fields to
    // mint data keys that are then thrown away.
    let (cipher, generates, _) = counting_cipher().await;
    let a = "a".to_string();
    let b = "b".to_string();

    let zipped = StackCipherText::encrypt_from(&a, &cipher, "")
        .zip(StackCipherText::encrypt_from(&b, &cipher, "users/x"))
        .await;
    assert!(matches!(zipped, Err(Error::EmptyContext)));

    let column = Pending::all(
        &cipher,
        vec![
            StackCipherText::encrypt_from(&b, &cipher, "users/x"),
            StackCipherText::encrypt_from(&a, &cipher, ""),
        ],
    )
    .await;
    assert!(matches!(column, Err(Error::EmptyContext)));

    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        0,
        "a failed sibling must drop the batch, not dispatch it"
    );
}

#[tokio::test]
async fn pendings_from_different_ciphers_refuse_to_merge() {
    let (cipher_a, generates, _) = counting_cipher().await;
    let cipher_b = counting_cipher().await.0;
    let v = "v".to_string();
    let w = "w".to_string();

    let zipped = StackCipherText::encrypt_from(&v, &cipher_a, "users/x")
        .zip(StackCipherText::encrypt_from(&w, &cipher_b, "users/x"))
        .await;
    assert!(matches!(zipped, Err(Error::CipherMismatch)));

    let column = Pending::all(
        &cipher_a,
        vec![
            StackCipherText::encrypt_from(&v, &cipher_a, "users/x"),
            StackCipherText::encrypt_from(&w, &cipher_b, "users/x"),
        ],
    )
    .await;
    assert!(matches!(column, Err(Error::CipherMismatch)));

    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

#[tokio::test]
async fn an_overdrawing_fulfilment_is_a_response_shape_error() {
    // A fulfilment is scoped to exactly the responses its requests asked for:
    // drawing more must fail loudly, never consume a sibling's responses.
    let cipher = stack_cipher().await;

    let pending: Pending<'_, (), _> =
        Pending::request(&cipher, vec![Request::generate_data_key()], |responses| {
            responses.next_generated_key()?;
            responses.next_generated_key()?; // one more than requested
            Ok(())
        });

    assert!(matches!(pending.await, Err(Error::ResponseShape)));
}

// Terms rebuilt from persisted parts must behave like freshly generated ones.
#[tokio::test]
async fn terms_rehydrate_from_persisted_parts() {
    let generator = generator().await;

    let eq: EqualityTerm = "alice"
        .encrypt_into_with_context(&generator, "users/email")
        .await
        .unwrap();
    let rehydrated = EqualityTerm::from_bytes(eq.clone().into_bytes());
    assert_eq!(eq, rehydrated);

    let stored: MatchTerm = "alice wonderland"
        .to_string()
        .encrypt_into_with_context(&generator, "users/bio")
        .await
        .unwrap();
    let query: MatchTerm = "wonder"
        .to_string()
        .encrypt_into_with_context(&generator, "users/bio")
        .await
        .unwrap();
    // Rehydrate from unsorted positions: from_positions normalises.
    let mut positions = stored.clone().into_positions();
    positions.reverse();
    let rehydrated: MatchTerm = MatchTerm::from_positions(positions);
    assert_eq!(stored, rehydrated);
    assert!(rehydrated.contains(&query));
}

// The pending futures are `Send` on native targets, so target-directed
// encryption can hop threads (e.g. `tokio::spawn`).
#[tokio::test]
async fn pending_futures_are_send() {
    let generator = generator().await;

    let handle = tokio::spawn(async move {
        let term: EqualityTerm = "alice"
            .encrypt_into_with_context(&generator, "users/email")
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

    let names: Vec<String> = ["ada", "grace", "edsger", "barbara"]
        .into_iter()
        .map(String::from)
        .collect();
    let ct = cipher.encrypt(names.clone(), "users/name").await.unwrap();
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
    let value = vec!["one".to_string(), "two".to_string(), "three".to_string()];

    // Sealed by the cipher-directed API, opened by the target-directed one.
    let ct = cipher.encrypt(value.clone(), "users/tags").await.unwrap();
    let via_target: Vec<String> = ct.decrypt_into(&cipher, "users/tags").await.unwrap();
    assert_eq!(via_target, value);

    // Sealed by the target-directed API, opened by the cipher-directed one.
    let ct: StackCipherText = value
        .encrypt_into_with_context(&cipher, "users/tags")
        .await
        .unwrap();
    let via_cipher: Vec<String> = cipher.decrypt(ct, "users/tags").await.unwrap();
    assert_eq!(via_cipher, value);
}

#[tokio::test]
async fn cipher_directed_decrypt_rejects_a_transplanted_ciphertext() {
    let cipher = stack_cipher().await;
    let ct: StackCipherText = "secret"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/email")
        .await
        .unwrap();
    let result: Result<String, Error> = cipher.decrypt(ct, "users/name").await;
    assert!(
        matches!(result, Err(Error::Aead)),
        "a target-sealed leaf must not open under another context via the cipher API"
    );
}
