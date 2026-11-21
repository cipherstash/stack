//! The derive writes what the combinators write: what `#[derive(EncryptTarget)]`
//! generates must write exactly what the same declaration written out by hand
//! with the combinators of `stack_encrypt::target` writes. Each `Legacy*` type
//! below is such a declaration. Each test runs it beside the derived record
//! and compares what ZeroKMS is sent and the terms, and opens the hand-written
//! record's ciphertext through the derived record.

mod common;

use std::sync::atomic::Ordering as AtomicOrdering;

use common::{counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreTerm};
use stack_encrypt::target::{
    AeadContext, CallerContext, DeclaredContext, DeclaredScopes, DecryptField, DecryptSource,
    Decryptable, Decryption, EncryptTarget, Encrypted, Encryption, IndexSpec, RequiredContext,
};
use stack_encrypt::{
    nonempty, DecryptFrom, EmptyError, EncryptInto, Error, NonEmpty, PlanError, StackCipherText,
};
use zeroize::Zeroize;

// --- A `plaintext = T` record ------------------------------------------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Email {
    c: StackCipherText,
    hm: EqualityTerm,
}

/// `Email`'s declaration, written by hand.
struct LegacyEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptTarget<String> for LegacyEmail {
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput>
    where
        String: 's,
    {
        <StackCipherText as EncryptTarget<String>>::encryption::<K>()
            .accepting::<CallerContext>()
            .zip(
                <EqualityTerm as EncryptTarget<String>>::encryption::<K>()
                    .accepting::<CallerContext>(),
            )
            .accepting::<Self::ContextInput>()
            .map(move |(c, hm)| Self { c, hm })
    }
}

#[tokio::test]
async fn a_plaintext_record_writes_what_the_hand_written_combinators_write() {
    // A context of one escaped part, a two-part one and an integer: the
    // caller's context must reach the outputs as given, never as a label.
    for (n, context) in [
        CallerContext::from(nonempty!("users/email")),
        CallerContext::from(nonempty!("users").with("email")),
        CallerContext::from(7u64),
    ]
    .into_iter()
    .enumerate()
    {
        let (cipher, sent) = recording_cipher().await;
        let keyset = cipher.default_keyset();
        let value = format!("alice{n}@example.com");

        let derived: Email = value
            .clone()
            .encrypt_into_with_context(&keyset, context.clone())
            .await
            .unwrap();
        let legacy: LegacyEmail = value
            .clone()
            .encrypt_into_with_context(&keyset, context.clone())
            .await
            .unwrap();
        assert_eq!(derived.hm, legacy.hm, "the same term");
        {
            let sent = sent.lock().unwrap();
            assert_eq!(sent.generate.len(), 2, "one request per record");
            let generated = sent.generated();
            assert_eq!(generated.len(), 2);
            assert_eq!(generated[0], generated[1], "the same descriptor");
        }

        // The hand-written record opens through the derived record's reader,
        // and the derived record's ciphertext opens as a leaf.
        let crossed = Email {
            c: legacy.c,
            hm: legacy.hm,
        };
        let opened = String::decrypt_from_with_context(crossed, &cipher, context.clone())
            .await
            .unwrap();
        assert_eq!(opened, value);
        let opened =
            String::decrypt_from_with_context(derived.c, &keyset, AeadContext::from(context))
                .await
                .unwrap();
        assert_eq!(opened, value);
    }
}

#[test]
fn a_plaintext_record_answers_the_queries_its_terms_answer() {
    assert_eq!(
        <Email as EncryptTarget<String>>::indexes(),
        vec![IndexSpec::Equality]
    );
    // A record used as a field names what its type declares: `Age` names ORE.
    assert_eq!(<Age as EncryptTarget<u32>>::indexes(), vec![IndexSpec::Ore]);
}

// --- A record with five outputs ----------------------------------------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct Wide {
    #[stash(decrypt)]
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
    shadow: StackCipherText,
    twin: StackCipherText,
}

#[tokio::test]
async fn five_outputs_nest_and_each_is_derived_under_the_one_context() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("readings");

    let wide: Wide = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let hm: EqualityTerm = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let ob: OreTerm<u32> = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(wide.hm, hm);
    assert_eq!(wide.ob, ob);
    assert_eq!(
        <Wide as EncryptTarget<u32>>::indexes().len(),
        2,
        "equality and ORE: a record declares one order index"
    );
    let shadow = u32::decrypt_from_with_context(wide.shadow, &cipher, context())
        .await
        .unwrap();
    assert_eq!(shadow, 9);
    let twin = u32::decrypt_from_with_context(wide.twin, &cipher, context())
        .await
        .unwrap();
    assert_eq!(twin, 9);
    let wide: Wide = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let opened = u32::decrypt_from_with_context(wide, &cipher, context())
        .await
        .unwrap();
    assert_eq!(opened, 9);
}

// --- A record that stores its context -----------------------------------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Scoped {
    #[stash(context_field)]
    i: String,
    c: StackCipherText,
    hm: EqualityTerm,
    #[stash(default = 3)]
    v: u8,
}

/// `Scoped`'s declaration, written by hand: the outputs run under the
/// caller's context, and the record keeps a copy of it.
struct LegacyScoped {
    i: String,
    c: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptTarget<String> for LegacyScoped {
    type ContextInput = RequiredContext<NonEmpty<String>>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput>
    where
        String: 's,
    {
        <StackCipherText as EncryptTarget<String>>::encryption::<K>()
            .accepting::<CallerContext>()
            .zip(
                <EqualityTerm as EncryptTarget<String>>::encryption::<K>()
                    .accepting::<CallerContext>(),
            )
            .accepting::<Self::ContextInput>()
            .map_with_context(move |(c, hm), context| Self {
                i: context.into_inner().into_inner(),
                c,
                hm,
            })
    }
}

fn tenant() -> NonEmpty<String> {
    NonEmpty::new("tenants/acme/email".to_string()).unwrap()
}

#[tokio::test]
async fn a_context_field_record_writes_what_the_hand_written_combinators_write() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();

    let derived: Scoped = value
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let legacy: LegacyScoped = value
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    assert_eq!(derived.i, legacy.i);
    assert_eq!(derived.i, "tenants/acme/email");
    assert_eq!(derived.v, 3);
    assert_eq!(derived.hm, legacy.hm);
    {
        let sent = sent.lock().unwrap();
        let generated = sent.generated();
        assert_eq!(generated.len(), 2);
        assert_eq!(generated[0], generated[1]);
    }

    let crossed = Scoped {
        i: legacy.i,
        c: legacy.c,
        hm: legacy.hm,
        v: 3,
    };
    let opened = String::decrypt_from_with_context(crossed, &cipher, tenant())
        .await
        .unwrap();
    assert_eq!(opened, value);
}

#[tokio::test]
async fn a_context_field_record_refuses_an_empty_stored_context_before_any_request() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();
    let sealed: Scoped = value
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();

    // The stored context is not authenticated: a row can hold an empty one.
    let emptied = Scoped {
        i: String::new(),
        ..sealed
    };
    let refused = String::decrypt_from(emptied, &keyset).await;
    // The empty-context refusal, not a mismatch: with no expected context
    // there is nothing for the stored one to differ from.
    assert!(
        matches!(&refused, Err(Error::Other(error)) if error.is::<EmptyError>()),
        "{refused:?}"
    );
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 0);
}

// --- A record of ciphertexts alone takes an AEAD-only context -----------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct Shadowed {
    #[stash(decrypt)]
    c: StackCipherText,
    shadow: StackCipherText,
}

#[tokio::test]
async fn a_record_of_ciphertexts_takes_an_aead_context() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "x".to_string();
    let context = || AeadContext::from(nonempty!("names"));

    let record: Shadowed = value
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["names", "names"]);
    let opened = String::decrypt_from_with_context(record.shadow, &keyset, context())
        .await
        .unwrap();
    assert_eq!(opened, value);
    let opened = String::decrypt_from_with_context(record.c, &cipher, context())
        .await
        .unwrap();
    assert_eq!(opened, value);
}

// --- A `struct` record ---------------------------------------------------------

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct User {
    email: String,
    name: String,
    age: u32,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct Age {
    c: StackCipherText,
    ob: OreTerm<u32>,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Encrypted<EqualityTerm>,
    #[stash(identity = "nickname")]
    name: StackCipherText,
    age: Age,
    #[stash(default = 3)]
    v: u8,
}

/// `EncryptedUser`'s declaration, written by hand: each field's target over
/// its plaintext field, under the field's own context.
struct LegacyUser {
    email: Encrypted<EqualityTerm>,
    name: StackCipherText,
    age: Age,
}

impl EncryptTarget<User> for LegacyUser {
    type ContextInput = DeclaredScopes;
    fn encryption<'s, K: 'static>() -> Encryption<'s, User, Self, K, Self::ContextInput>
    where
        User: 's,
    {
        <Encrypted<EqualityTerm> as EncryptTarget<String>>::encryption::<K>()
            .project(|u: &User| &u.email)
            .under(nonempty!("users").with("email"))
            .zip(
                <StackCipherText as EncryptTarget<String>>::encryption::<K>()
                    .project(|u: &User| &u.name)
                    .under(nonempty!("users").with("nickname")),
            )
            .zip(
                <Age as EncryptTarget<u32>>::encryption::<K>()
                    .project(|u: &User| &u.age)
                    .under(nonempty!("users").with("age")),
            )
            .accepting::<Self::ContextInput>()
            .map(move |((email, name), age)| Self { email, name, age })
    }
}

fn user() -> User {
    User {
        email: "alice@example.com".into(),
        name: "Alice".into(),
        age: 34,
    }
}

/// The record as a caller runs it: the plaintext by value, and no context.
#[tokio::test]
async fn a_struct_record_writes_what_the_hand_written_combinators_write() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let derived: EncryptedUser = user().encrypt_into(&keyset).await.unwrap();
    let legacy: LegacyUser = user().encrypt_into(&keyset).await.unwrap();
    assert_eq!(derived.v, 3);
    assert_eq!(derived.email.terms, legacy.email.terms);
    assert_eq!(derived.age.ob, legacy.age.ob);
    {
        let sent = sent.lock().unwrap();
        assert_eq!(sent.generate.len(), 2, "one request per record");
        assert_eq!(
            sent.generate[0], sent.generate[1],
            "the same descriptors, in the same order"
        );
        // Each field under the record's scope and its own segment, the
        // pinned identity in place of the field's name.
        assert_eq!(
            sent.generate[0],
            ["users/email", "users/nickname", "users/age"]
        );
    }

    let crossed = EncryptedUser {
        email: legacy.email,
        name: legacy.name,
        age: legacy.age,
        v: 3,
    };
    let opened = User::decrypt_from(crossed, &cipher).await.unwrap();
    assert_eq!(opened, user());
}

/// The record as a record that contains it runs it: the plaintext borrowed,
/// and each field's context extended by the context it is handed.
#[tokio::test]
async fn a_struct_record_handed_a_context_writes_what_the_hand_written_combinators_write() {
    for extend in [DeclaredContext::from(()), DeclaredContext::from(7u64)] {
        let (cipher, sent) = recording_cipher().await;
        let keyset = cipher.default_keyset();
        let plaintext = user();

        let derived: EncryptedUser = keyset
            .run(
                <EncryptedUser as EncryptTarget<User>>::encryption(),
                &plaintext,
                DeclaredScopes::from(extend.clone()),
            )
            .await
            .unwrap();
        let legacy: LegacyUser = keyset
            .run(
                <LegacyUser as EncryptTarget<User>>::encryption(),
                &plaintext,
                DeclaredScopes::from(extend.clone()),
            )
            .await
            .unwrap();
        assert_eq!(derived.v, 3);
        assert_eq!(derived.email.terms, legacy.email.terms);
        assert_eq!(derived.age.ob, legacy.age.ob);
        {
            let sent = sent.lock().unwrap();
            assert_eq!(sent.generate.len(), 2, "one request per record");
            assert_eq!(
                sent.generate[0], sent.generate[1],
                "the same descriptors, in the same order"
            );
        }

        let crossed = EncryptedUser {
            email: legacy.email,
            name: legacy.name,
            age: legacy.age,
            v: 3,
        };
        let opened: User = cipher
            .run_decryption(crossed.decryption(DeclaredScopes::from(extend)))
            .await
            .unwrap();
        assert_eq!(opened, user());
    }
}

// --- A record whose ciphertext is last -----------------------------------------

/// Five outputs, its one ciphertext last.
#[allow(dead_code)] // only `hm` and the opening are read
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct CiphertextLast {
    hm: EqualityTerm,
    m: MatchTerms,
    ob: OreTerm<String>,
    shadow: StackCipherText,
    #[stash(decrypt)]
    c: StackCipherText,
}

#[tokio::test]
async fn the_one_decryptable_output_opens_when_it_is_the_last_field() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("names");
    let value = "alice".to_string();

    let record: CiphertextLast = value
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let hm: EqualityTerm = value
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    let opened = String::decrypt_from_with_context(record, &cipher, context())
        .await
        .unwrap();
    assert_eq!(opened, value);
}

// --- A record that declares its context type ----------------------------------

/// A ciphertext alone, under the record's `NonEmpty<u64>`: the ciphertext
/// takes the AEAD half of that context.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Tenanted {
    c: StackCipherText,
}

/// A term whose context is a `NonEmpty<u64>`, not a `CallerContext`.
#[derive(Debug, PartialEq)]
struct TenantTag(EqualityTerm);
impl EncryptTarget<String> for TenantTag {
    type ContextInput = RequiredContext<NonEmpty<u64>>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput> {
        <EqualityTerm as EncryptTarget<String>>::encryption()
            .accepting::<CallerContext>()
            .accepting::<Self::ContextInput>()
            .map(TenantTag)
    }
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Equality]
    }
}
impl Decryptable for TenantTag {
    const DECRYPTABLE: bool = false;
}
impl<P, Ctx> DecryptField<P, Ctx> for TenantTag {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}

/// One output, whose context is the record's `NonEmpty<u64>`.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct WrappedTenanted {
    inner: Tenanted,
}

/// Two outputs sharing the record's `NonEmpty<u64>`, one of them decryptable.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct TenantedPair {
    inner: Tenanted,
    tag: TenantTag,
}

/// A record declaring `context_type = NonEmpty<u64>` is sealed and opened
/// under that context, never a `CallerContext` it could not take, and
/// writes what its outputs write alone.
#[tokio::test]
async fn a_record_keeps_its_declared_context_type() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();
    let tenant = || NonEmpty::from(7u64);

    let wrapped: WrappedTenanted = value
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let opened = String::decrypt_from_with_context(wrapped, &cipher, tenant())
        .await
        .unwrap();
    assert_eq!(opened, value);

    let pair: TenantedPair = value
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let tag: TenantTag = value
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    assert_eq!(pair.tag, tag, "the record's term is the target's");
    let opened = String::decrypt_from_with_context(pair, &cipher, tenant())
        .await
        .unwrap();
    assert_eq!(opened, value);
}

// --- Two outputs that declare the same index ---------------------------------

/// A `plaintext` record whose two fields declare the equality index. Its
/// first field is a valid ciphertext, which would need a data key: the
/// refusal must stop that request too.
#[allow(dead_code)] // never built: refusing it is the point
#[derive(EncryptTarget)]
#[stash(plaintext = String)]
struct TwoEqualities {
    c: StackCipherText,
    hm: EqualityTerm,
    again: EqualityTerm,
}

/// The derive sees the fields' type names, not the indexes they declare. So
/// two fields that declare one index are refused when the record runs,
/// before any key is requested.
#[tokio::test]
async fn two_outputs_declaring_one_index_are_refused_before_any_request() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let result: Result<TwoEqualities, _> = "x"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("x"))
        .await;
    assert!(
        matches!(
            &result,
            Err(Error::Plan(PlanError::DuplicateIndex { index: "eq", .. }))
        ),
        "{:?}",
        result.err()
    );
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

/// A `plaintext` record with an ORE term and an OPE term: two indexes that
/// answer the orderings. Its first field is a valid ciphertext, as in
/// [`TwoEqualities`].
#[allow(dead_code)] // never built: refusing it is the point
#[derive(EncryptTarget)]
#[stash(plaintext = u32)]
struct TwoOrders {
    c: StackCipherText,
    ore: OreTerm<u32>,
    ope: OpeTerm<u32>,
}

#[tokio::test]
async fn two_outputs_that_answer_one_operator_are_refused_before_any_request() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let result: Result<TwoOrders, _> = 7u32
        .encrypt_into_with_context(&keyset, nonempty!("x"))
        .await;
    assert!(
        matches!(
            &result,
            Err(Error::Plan(PlanError::IndexOverlap {
                first: "ore",
                second: "ope",
                ..
            }))
        ),
        "{:?}",
        result.err()
    );
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

/// A `struct` record whose field type declares one index twice. The field's
/// type refuses it, when the record runs.
#[allow(dead_code)] // never built: refusing it is the point
#[derive(EncryptTarget)]
#[stash(struct = Named, scope = "users")]
struct TwoEqualitiesInAField {
    email: Encrypted<(EqualityTerm, EqualityTerm)>,
}

#[derive(Clone, Zeroize)]
struct Named {
    email: String,
}

#[tokio::test]
async fn a_field_declaring_one_index_twice_is_refused_before_any_request() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let named = Named {
        email: "bob@example.com".to_string(),
    };
    // By value, and through a borrow: the two forms of the declaration.
    let owned: Result<TwoEqualitiesInAField, _> = named.clone().encrypt_into(&keyset).await;
    let borrowed: Result<TwoEqualitiesInAField, _> = keyset
        .run(
            <TwoEqualitiesInAField as EncryptTarget<Named>>::encryption(),
            &named,
            DeclaredScopes::from(DeclaredContext::default()),
        )
        .await;
    for result in [owned, borrowed] {
        assert!(
            matches!(
                &result,
                Err(Error::Plan(PlanError::DuplicateIndex { index: "eq", .. }))
            ),
            "{:?}",
            result.err()
        );
    }
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

// --- A refused set of indexes keeps its contexts -----------------------------

/// A refused set of indexes is refused when it runs, and its fields still
/// show in `contexts()`: the declaration names them, and the refusal is
/// reported when the call is awaited.
#[test]
fn a_refused_set_of_indexes_keeps_its_fields_contexts() {
    // Refused by the derive: two fields whose indexes answer one operator.
    assert_eq!(
        TwoOrders::contexts().to_string(),
        "c\n  context: {context: CallerContext}\n\
         ore\n  context: {context: CallerContext}\n\
         ope\n  context: {context: CallerContext}\n"
    );
    // Refused by the field's type: one index named twice.
    assert_eq!(
        TwoEqualitiesInAField::contexts().to_string(),
        "email\n  context: users / email\n"
    );
}
