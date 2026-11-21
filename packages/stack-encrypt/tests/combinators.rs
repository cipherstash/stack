//! The combinators of `stack_encrypt::target` are the one engine every
//! declaration runs through, and the bytes are theirs.
//!
//! A derived record, a target named by its type, and a query from a field
//! reference each write what the combinators write when a test composes
//! them by hand: `indexed(..).under(label)` for a sealed field with terms,
//! `ciphertext().under(label)` for a sealed field, an index's own operation
//! for a term alone, `passthrough()` for a field carried as it is, and
//! `project` and `zip` to make a record of them. The tests run the
//! hand-composed description with `KeysetCipher::run` beside each
//! declaration and compare the descriptors sent to ZeroKMS, the terms byte
//! for byte, and that each side opens what the other sealed.
//!
//! The rest of the file holds what follows from one engine: a caller's
//! context extends every field, `Pending::zip` and `Pending::all` settle
//! several operations with at most one ZeroKMS request of each kind (one
//! generate request and one retrieve request), nothing is requested before
//! an await, and every operation runs under the keyset it is given.
mod common;

use std::fmt::Debug;
use std::sync::atomic::Ordering;

use common::{counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::kms::{FakeDataKeySource, IdentifiedBy};
use stack_encrypt::sem::{
    EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OpeTerm, OreBlockTerm, OreTerm, Tokenizer,
};
use stack_encrypt::target::{
    self, equality, indexed, matching, open, passthrough, AeadContext, AllowsNoContext, Borrowed,
    CallerContext, DeclaredContext, DecryptField, DecryptSource, Decryptable, Decryption,
    EncryptTarget, Encrypted, Encryption, IndexSpec, Indexes, RequiredContext, Scope, TermSet,
};
use stack_encrypt::{
    nonempty, CipherText, Decrypt, DecryptFrom, Encrypt, EncryptInto, Equality, Error,
    KeysetCipher, Label, Match, NonEmpty, Ope, Ore, OreBlock, Pending, PlanError, StackCipherText,
};
use zeroize::Zeroize;

/// The record most tests encrypt: two indexed fields, one sealed alone,
/// one carried through.
#[derive(Clone, Debug, PartialEq, Zeroize)]
struct User {
    email: String,
    age: u32,
    notes: String,
    id: u64,
}

fn user() -> User {
    User {
        email: "bob@example.com".into(),
        age: 34,
        notes: "likes cheese".into(),
        id: 42,
    }
}

type EmailTerms = (EqualityTerm, MatchTerms);
type AgeTerms = (EqualityTerm, OreTerm<u32>);

/// The derived record: each sealed field under `users/<field>`.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Encrypted<EmailTerms>,
    age: Encrypted<AgeTerms>,
    notes: StackCipherText,
    #[stash(passthrough)]
    id: u64,
}

/// The same record, whose caller supplies a tenant on every call.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct TenantUser {
    email: Encrypted<EmailTerms>,
    age: Encrypted<AgeTerms>,
    notes: StackCipherText,
    #[stash(passthrough)]
    id: u64,
}

fn plan_error<T: Debug>(result: Result<T, Error>) -> PlanError {
    match result {
        Err(Error::Plan(error)) => error,
        other => panic!("expected a plan error, got {other:?}"),
    }
}

fn leaf_keyset(ciphertext: &StackCipherText) -> uuid::Uuid {
    match ciphertext {
        CipherText::Single(leaf) => leaf.keyset_id(),
        other => panic!("expected a single leaf, got {other:?}"),
    }
}

/// The hand-composed combinator spelling of the four-field record, each
/// field under the derive's spelling of its context.
type HandOut = (
    (
        (Encrypted<EmailTerms>, Encrypted<AgeTerms>),
        StackCipherText,
    ),
    u64,
);
fn hand_composed<'s, K: 'static>() -> Encryption<'s, User, HandOut, K, DeclaredContext> {
    indexed::<String, _, Borrowed, _>((Equality, Match))
        .under(nonempty!("users").with("email"))
        .project(|u: &User| &u.email)
        .zip(
            indexed::<u32, _, Borrowed, _>((Equality, Ore))
                .under(nonempty!("users").with("age"))
                .project(|u: &User| &u.age),
        )
        .zip(
            target::ciphertext::<String, _, Borrowed>()
                .under(nonempty!("users").with("notes"))
                .project(|u: &User| &u.notes),
        )
        .zip(passthrough::<u64, _, Borrowed, DeclaredContext>().project(|u: &User| &u.id))
}

/// One document sealed alone under `docs`, as a pending operation.
fn seal_doc<'a, K: 'static>(keyset: &'a KeysetCipher<'_, K>) -> Pending<'a, StackCipherText, K> {
    String::from("doc").encrypt_into_with_context(keyset, nonempty!("docs"))
}

// --- A derived record is the combinators ---------------------------------------

#[tokio::test]
async fn a_derived_record_is_the_hand_composed_combinators_field_for_field() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let user = user();

    let derived: EncryptedUser = user.clone().encrypt_into(&keyset).await.unwrap();
    let derived_sent = sent.lock().unwrap().generated();
    sent.lock().unwrap().generate.clear();

    let (((email, age), notes), id) = keyset
        .run(hand_composed(), &user, DeclaredContext::default())
        .await
        .unwrap();
    let hand_sent = sent.lock().unwrap().generated();

    assert_eq!(
        derived_sent, hand_sent,
        "every data key under the same descriptor"
    );
    assert_eq!(
        derived_sent,
        ["users/email", "users/age", "users/notes"],
        "one key per sealed field, under <scope>/<field>"
    );
    assert_eq!(derived.id, id, "passthrough is the value");
    assert_eq!(derived.email.terms.0, email.terms.0, "email equality term");
    assert_eq!(
        derived.email.terms.1.to_bytes(),
        email.terms.1.to_bytes(),
        "email match terms"
    );
    assert_eq!(derived.age.terms.0, age.terms.0, "age equality term");
    assert_eq!(
        derived.age.terms.1.to_bytes(),
        age.terms.1.to_bytes(),
        "age ORE term"
    );

    // Ciphertexts are randomised, so they are compared by opening each
    // side's with the other's reader. The derived record's fields open
    // through the cipher under the labels the combinators sealed under.
    let cipher = &cipher;
    let open = |ct: StackCipherText, field: &str| {
        let context = nonempty!("users").with(field.to_owned());
        async move { cipher.decrypt::<String, _>(ct, context).await }
    };
    assert_eq!(
        open(derived.email.ciphertext, "email").await.unwrap(),
        user.email
    );
    assert_eq!(open(derived.notes, "notes").await.unwrap(), user.notes);
    let derived_age: u32 = cipher
        .decrypt(derived.age.ciphertext, nonempty!("users").with("age"))
        .await
        .unwrap();
    assert_eq!(derived_age, user.age);

    // And the hand-composed fields open as the derived record.
    let hand_row = EncryptedUser {
        email,
        age,
        notes,
        id,
    };
    let back = User::decrypt_from(hand_row, cipher).await.unwrap();
    assert_eq!(back, user);
}

#[tokio::test]
async fn a_field_query_derives_under_the_label_the_write_used() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    // The stored terms are the combinators', so a query that matches them
    // is derived as the combinators derive.
    let (((email, age), _), _) = keyset
        .run(hand_composed(), &user(), DeclaredContext::default())
        .await
        .unwrap();

    let eq: EqualityTerm = EncryptedUser::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(
        eq, email.terms.0,
        "equality query bytes equal the stored term"
    );
    let matching = EncryptedUser::EMAIL
        .matches("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(matching.to_bytes(), email.terms.1.to_bytes());
    let ore: OreTerm<u32> = EncryptedUser::AGE.lt(34u32).encrypt(&keyset).await.unwrap();
    assert_eq!(ore.to_bytes(), age.terms.1.to_bytes());
    let by_age: EqualityTerm = EncryptedUser::AGE.eq(34u32).encrypt(&keyset).await.unwrap();
    assert_eq!(by_age, age.terms.0, "each operator through its own index");

    // A different value is a different term: the query is not a constant.
    let other = EncryptedUser::EMAIL
        .eq("eve@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(other, email.terms.0);
}

/// A record whose `email` is its terms alone: searchable, and not stored.
#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct IndexedUser {
    email: EqualityTerm,
    age: StackCipherText,
    notes: StackCipherText,
    #[stash(passthrough)]
    id: u64,
}

/// A field of terms alone asks for no data key, a query of the field
/// matches the stored term, and the term is the bytes a sealed field
/// stores beside its ciphertext.
#[tokio::test]
async fn a_field_of_terms_alone_matches_its_query_and_mints_no_data_key() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let row: IndexedUser = user().encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["users/age", "users/notes"],
        "a field of terms alone asks for no data key"
    );
    assert_eq!(row.id, 42);
    let age: u32 = cipher
        .decrypt(row.age, nonempty!("users").with("age"))
        .await
        .unwrap();
    assert_eq!(age, 34, "the fields beside it are sealed as before");
    let notes: String = cipher
        .decrypt(row.notes, nonempty!("users").with("notes"))
        .await
        .unwrap();
    assert_eq!(notes, "likes cheese");

    let query = IndexedUser::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(
        query, row.email,
        "the query derives under the write's label"
    );

    // Byte-identical to the term the combinators derive alone, and to the
    // terms a sealed field writes for the same field.
    sent.lock().unwrap().generate.clear();
    let (eq, matched): EmailTerms = keyset
        .run(
            Indexes::<String>::operations::<_, Borrowed>(&(Equality, Match))
                .under(nonempty!("users").with("email")),
            &user().email,
            DeclaredContext::default(),
        )
        .await
        .unwrap();
    assert!(
        sent.lock().unwrap().generated().is_empty(),
        "the indexes' operations ask for no data key"
    );
    assert_eq!(eq, row.email);
    let sealed: EncryptedUser = user().encrypt_into(&keyset).await.unwrap();
    assert_eq!(eq, sealed.email.terms.0);
    assert_eq!(matched.to_bytes(), sealed.email.terms.1.to_bytes());
}

/// A record with a field keyed under another segment than its name.
#[derive(Clone, Zeroize)]
struct Secret {
    totp: String,
    attempts: u32,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Secret, scope = "users")]
struct EncryptedSecret {
    #[stash(identity = "totp_secret")]
    totp: StackCipherText,
    #[stash(identity = "value")]
    attempts: Encrypted<EqualityTerm>,
}

/// A pinned identity keys the field: the write, the query and the read all
/// use `<scope>/<identity>`, never the field's name.
#[tokio::test]
async fn a_pinned_identity_keys_the_field_for_the_write_the_query_and_the_read() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    assert_eq!(
        EncryptedSecret::TOTP.label().to_string(),
        "users/totp_secret"
    );
    assert_eq!(EncryptedSecret::TOTP.name(), "totp");
    let secret = Secret {
        totp: "s".into(),
        attempts: 21,
    };
    let record: EncryptedSecret = secret.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["users/totp_secret", "users/value"]
    );

    // The same bytes as the combinators under the pinned label.
    let by_hand: Encrypted<EqualityTerm> = keyset
        .run(
            indexed::<u32, _, Borrowed, _>(Equality).under(nonempty!("users").with("value")),
            &21u32,
            DeclaredContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(record.attempts.terms, by_hand.terms);
    let query = EncryptedSecret::ATTEMPTS
        .eq(21u32)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query, record.attempts.terms);
    let opened: u32 = cipher
        .decrypt(record.attempts.ciphertext, nonempty!("users").with("value"))
        .await
        .unwrap();
    assert_eq!(opened, 21);
    let totp: String = cipher
        .decrypt(record.totp, nonempty!("users").with("totp_secret"))
        .await
        .unwrap();
    assert_eq!(totp, "s");

    // The derived reader opens each field under its pinned identity too.
    let record: EncryptedSecret = secret.encrypt_into(&keyset).await.unwrap();
    let opened = Secret::decrypt_from(record, &keyset).await.unwrap();
    assert_eq!(opened.totp, "s");
    assert_eq!(opened.attempts, 21);
}

/// A target that says it holds ciphertext and then opens nothing.
#[allow(dead_code)] // never read: it only says it holds ciphertext
struct Lying(StackCipherText);
impl EncryptTarget<u32> for Lying {
    type ContextInput = RequiredContext<AeadContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, u32, Self, K, Self::ContextInput> {
        <StackCipherText as EncryptTarget<u32>>::encryption().map(Lying)
    }
}
impl Decryptable for Lying {
    const DECRYPTABLE: bool = true;
}
impl<P, Ctx> DecryptField<P, Ctx> for Lying {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}

#[derive(Clone, Zeroize)]
struct Counter {
    count: u32,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Counter, scope = "counters")]
struct LyingCounter {
    count: Lying,
}

#[tokio::test]
async fn a_field_that_opens_nothing_is_not_opened() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let record: LyingCounter = Counter { count: 7 }.encrypt_into(&keyset).await.unwrap();
    let result = Counter::decrypt_from(record, &keyset).await;
    assert!(
        matches!(result.as_ref().map(|c| c.count), Err(Error::NotOpened)),
        "the record is refused, not opened without its field"
    );
}

// --- A record of one plaintext is the combinators ---------------------------------

/// One value, sealed with its equality term beside it, under the one
/// context the caller supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct DerivedEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

#[tokio::test]
async fn a_plaintext_record_is_the_combinators_bytes() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || CallerContext::from(nonempty!("users").with("email"));
    let email = String::from("bob@example.com");

    // The ciphertext takes the AEAD half of the context its term takes.
    let (c, hm): (StackCipherText, EqualityTerm) = keyset
        .run(
            target::ciphertext::<String, _, Borrowed>()
                .accepting::<CallerContext>()
                .zip(equality()),
            &email,
            context(),
        )
        .await
        .unwrap();
    let derived: DerivedEmail = email
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["users/email", "users/email"]
    );
    assert_eq!(hm, derived.hm, "the same equality term");

    // The record answers the query its term answers: the term alone,
    // under the same context.
    let query: EqualityTerm = email
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(query, derived.hm);

    // Each ciphertext opens through the other's reader.
    let opened =
        String::decrypt_from_with_context(DerivedEmail { c, hm: hm.clone() }, &cipher, context())
            .await
            .unwrap();
    assert_eq!(opened, email);
    let back: String = cipher
        .run_decryption(open(derived.c, context()))
        .await
        .unwrap();
    assert_eq!(back, email);
}

/// A record whose terms come before its ciphertext.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct TermsFirst {
    hm: EqualityTerm,
    ore: OreTerm<u32>,
    c: StackCipherText,
}

/// A term is no field to open a record through: it yields to the
/// ciphertext beside it, wherever the ciphertext sits.
#[tokio::test]
async fn a_record_opens_through_its_ciphertext_wherever_it_sits() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || CallerContext::from(nonempty!("t"));

    let record: TermsFirst = 7u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let by_hand: Encrypted<(EqualityTerm, OreTerm<u32>)> = keyset
        .run(
            indexed::<u32, _, Borrowed, _>((Equality, Ore)),
            &7u32,
            context(),
        )
        .await
        .unwrap();
    assert_eq!(record.hm, by_hand.terms.0);
    assert_eq!(record.ore.to_bytes(), by_hand.terms.1.to_bytes());
    let opened = u32::decrypt_from_with_context(record, &cipher, context())
        .await
        .unwrap();
    assert_eq!(opened, 7);

    // A term opens nothing, and the ciphertext opens under the context.
    let term: Option<Decryption<u32, FakeDataKeySource>> =
        by_hand.terms.0.clone().decryption_field(context());
    assert!(term.is_none(), "a term alone opens nothing");
    let opening: Option<Decryption<u32, FakeDataKeySource>> = by_hand.decryption_field(context());
    let opened = cipher.run_decryption(opening.unwrap()).await.unwrap();
    assert_eq!(opened, 7);
}

// --- One value ---------------------------------------------------------------

#[tokio::test]
async fn one_value_with_indexes_is_the_indexed_combinator_and_reads_back() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("users").with("age");
    let out: Encrypted<AgeTerms> = 34u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();

    // Byte-identical to the combinator, under the same label.
    let hand = keyset
        .run(
            indexed::<u32, _, Borrowed, _>((Equality, Ore)),
            &34u32,
            CallerContext::from(NonEmpty::from(Label::parse("users/age").unwrap())),
        )
        .await
        .unwrap();
    assert_eq!(hand.terms.0, out.terms.0);
    assert_eq!(hand.terms.1.to_bytes(), out.terms.1.to_bytes());

    // A term alone, under the same context, is the term stored beside the
    // ciphertext: what a query for the value sends.
    let eq: EqualityTerm = 34u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(eq, out.terms.0);
    let ore: OreTerm<u32> = 34u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(ore.to_bytes(), out.terms.1.to_bytes());

    let age = u32::decrypt_from_with_context(out, &cipher, context())
        .await
        .unwrap();
    assert_eq!(age, 34);
    let age = u32::decrypt_from_with_context(hand.ciphertext, &cipher, context())
        .await
        .unwrap();
    assert_eq!(age, 34, "a bare ciphertext opens too");
}

#[tokio::test]
async fn one_tree_under_a_label_is_the_ciphertext_combinator_under_it() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let body = String::from("the document");
    let label = Label::parse("documents/v2/body").unwrap();

    let tree = keyset.encrypt_tree(&body, &label).await.unwrap();
    let by_hand: StackCipherText = keyset
        .run(
            target::ciphertext::<String, _, Borrowed>().under(NonEmpty::from(label.clone())),
            &body,
            DeclaredContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["documents/v2/body", "documents/v2/body"]
    );
    for ciphertext in [tree, by_hand] {
        let back: String = cipher.decrypt(ciphertext, &label).await.unwrap();
        assert_eq!(back, body);
    }
    assert!(
        Label::parse("not//plain").is_err(),
        "a label is plain segments"
    );
}

// --- A target named by its type is the indexes named as values -----------------

/// `Encrypted<Terms>` as a target beside `indexed(indexes)`: the same
/// descriptors, the same terms, and each opens through the other's reader.
async fn same_field_bytes<F, Terms, X>(value: F, indexes: X)
where
    F: Encrypt + Decrypt + Clone + Zeroize + Send + Sync + PartialEq + Debug + 'static,
    Terms: TermSet<F> + PartialEq + Debug + Send,
    X: Indexes<F, Terms = Terms> + Send + Sync + 'static,
{
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("t").with("v");
    assert_eq!(
        <Encrypted<Terms> as EncryptTarget<F>>::indexes(),
        indexes.specs(),
        "the target declares the indexes the values name"
    );

    let typed: Encrypted<Terms> = value
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let data: Encrypted<Terms> = keyset
        .run(
            indexed::<F, _, Borrowed, _>(indexes).under(context()),
            &value,
            DeclaredContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["t/v", "t/v"]);
    assert_eq!(typed.terms, data.terms, "the same terms");

    let back: F = cipher.decrypt(typed.ciphertext, context()).await.unwrap();
    assert_eq!(
        back, value,
        "the cipher opens the typed target's ciphertext"
    );
    let back = F::decrypt_from_with_context(data, &keyset, context())
        .await
        .unwrap();
    assert_eq!(
        back, value,
        "the typed reader opens the combinator's output"
    );
}

/// A configuration other than the default.
struct Words;
impl MatchConfig for Words {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Standard,
            downcase: false,
            short_words: false,
            k: 4,
            m: 512,
        }
    }
}

type M = MatchTerms;
type W = MatchTerms<Words>;

#[tokio::test]
async fn a_typed_text_target_is_the_indexes_bytes_for_every_index_set() {
    let text = || String::from("Hello World");
    let ore = Ore;
    let ope = Ope;
    let eq = Equality;
    let m = Match::default;
    same_field_bytes::<_, EqualityTerm, _>(text(), eq).await;
    same_field_bytes::<_, M, _>(text(), m()).await;
    same_field_bytes::<_, W, _>(text(), Match::<Words>::new()).await;
    same_field_bytes::<_, OreTerm<String>, _>(text(), ore).await;
    same_field_bytes::<_, OpeTerm<String>, _>(text(), ope).await;
    same_field_bytes::<_, (EqualityTerm, M), _>(text(), (eq, m())).await;
    same_field_bytes::<_, (EqualityTerm, OreTerm<String>), _>(text(), (eq, ore)).await;
    same_field_bytes::<_, (EqualityTerm, OpeTerm<String>), _>(text(), (eq, ope)).await;
    same_field_bytes::<_, (M, OreTerm<String>), _>(text(), (m(), ore)).await;
    same_field_bytes::<_, (M, OpeTerm<String>), _>(text(), (m(), ope)).await;
    same_field_bytes::<_, (EqualityTerm, M, OreTerm<String>), _>(text(), (eq, m(), ore)).await;
    same_field_bytes::<_, (EqualityTerm, M, OpeTerm<String>), _>(text(), (eq, m(), ope)).await;
}

#[tokio::test]
async fn a_typed_integer_target_is_the_indexes_bytes_for_every_index_set() {
    same_field_bytes::<_, EqualityTerm, _>(7u32, Equality).await;
    same_field_bytes::<_, OreTerm<u32>, _>(7u32, Ore).await;
    same_field_bytes::<_, OpeTerm<u32>, _>(7u32, Ope).await;
    same_field_bytes::<_, (EqualityTerm, OreTerm<u32>), _>(7u32, (Equality, Ore)).await;
    same_field_bytes::<_, (EqualityTerm, OpeTerm<u32>), _>(7u32, (Equality, Ope)).await;
    same_field_bytes::<_, (OreTerm<u32>, EqualityTerm), _>(7u32, (Ore, Equality)).await;
    same_field_bytes::<_, OreBlockTerm<u32>, _>(7u32, OreBlock).await;
    same_field_bytes::<_, (EqualityTerm, OreBlockTerm<u32>), _>(7u32, (Equality, OreBlock)).await;
}

#[test]
fn every_target_declares_the_indexes_its_terms_answer() {
    assert_eq!(
        <EqualityTerm as EncryptTarget<String>>::indexes(),
        [IndexSpec::Equality]
    );
    assert_eq!(
        <MatchTerms<Words> as EncryptTarget<String>>::indexes(),
        [IndexSpec::Match(Words::options())]
    );
    assert_eq!(
        <OreTerm<u32> as EncryptTarget<u32>>::indexes(),
        [IndexSpec::Ore]
    );
    assert_eq!(
        <OpeTerm<u32> as EncryptTarget<u32>>::indexes(),
        [IndexSpec::Ope]
    );
    assert_eq!(
        <OreBlockTerm<u32> as EncryptTarget<u32>>::indexes(),
        [IndexSpec::OreBlock]
    );
    assert!(<StackCipherText as EncryptTarget<u32>>::indexes().is_empty());
    assert_eq!(
        <Encrypted<(OreTerm<u32>, EqualityTerm)> as EncryptTarget<u32>>::indexes(),
        [IndexSpec::Ore, IndexSpec::Equality]
    );
    assert_eq!(
        <DerivedEmail as EncryptTarget<String>>::indexes(),
        [IndexSpec::Equality],
        "a record of one plaintext declares the indexes of its terms"
    );
    assert_eq!(
        <TermsFirst as EncryptTarget<u32>>::indexes(),
        [IndexSpec::Equality, IndexSpec::Ore]
    );
}

/// Three terms over text: equality, and two match terms under different
/// options.
type TwoMatches = (EqualityTerm, M, W);

/// A record whose one field names the equality index twice.
#[derive(EncryptTarget)]
#[stash(struct = Counter, scope = "counters")]
#[allow(dead_code)] // never read: its declaration is refused
struct TwiceCounter {
    count: Encrypted<(EqualityTerm, EqualityTerm)>,
}

/// A target holds one term for each kind of index, so a target that names
/// an index twice is refused when it runs, before any key is requested:
/// alone, or as a field of a derived record. Two match indexes under
/// different options are still the match index twice.
#[tokio::test]
async fn a_target_that_names_an_index_twice_is_refused_before_any_key_request() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("t").with("v");

    let two_matches: Result<Encrypted<TwoMatches>, _> = String::from("Hello World")
        .encrypt_into_with_context(&keyset, context())
        .await;
    assert_eq!(
        plan_error(two_matches),
        PlanError::DuplicateIndex {
            at: "the value".into(),
            index: "match"
        }
    );
    let twice: Result<Encrypted<(EqualityTerm, EqualityTerm)>, _> =
        7u32.encrypt_into_with_context(&keyset, context()).await;
    assert_eq!(
        plan_error(twice),
        PlanError::DuplicateIndex {
            at: "the value".into(),
            index: "eq"
        }
    );
    let in_a_record: Result<TwiceCounter, _> = Counter { count: 7 }.encrypt_into(&keyset).await;
    assert!(matches!(
        plan_error(in_a_record.map(drop)),
        PlanError::DuplicateIndex { index: "eq", .. }
    ));
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");
}

// --- The caller's context -------------------------------------------------------

/// The context a field of the record is sealed under when the caller
/// supplies `parts`: the field's own label, extended by them.
fn extended(field: &'static str, parts: DeclaredContext) -> CallerContext {
    parts.under(nonempty!("users").with(field))
}

#[tokio::test]
async fn a_callers_part_extends_every_field_and_reading_back_needs_it() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let user = user();
    let (((email, _), _), _) = keyset
        .run(hand_composed(), &user, DeclaredContext::from(7u64))
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        [
            "(users/email)/7u64",
            "(users/age)/7u64",
            "(users/notes)/7u64"
        ]
    );
    // A derived record whose caller supplies the part sends the same.
    sent.lock().unwrap().generate.clear();
    let derived: TenantUser = user
        .clone()
        .encrypt_into_with_context(&keyset, Scope::new(7u64))
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        [
            "(users/email)/7u64",
            "(users/age)/7u64",
            "(users/notes)/7u64"
        ]
    );
    assert_eq!(derived.email.terms.0, email.terms.0);

    let back: String = cipher
        .run_decryption(open(
            derived.email.ciphertext,
            extended("email", DeclaredContext::from(7u64)),
        ))
        .await
        .unwrap();
    assert_eq!(back, "bob@example.com");

    let unextended: Result<String, _> = cipher
        .run_decryption(open(
            email.ciphertext,
            extended("email", DeclaredContext::default()),
        ))
        .await;
    assert!(
        matches!(unextended, Err(Error::Aead)),
        "the fake key source ignores descriptors, so a missing extension reaches the AEAD"
    );
    let row: TenantUser = user
        .encrypt_into_with_context(&keyset, Scope::new(7u64))
        .await
        .unwrap();
    let other = User::decrypt_from_with_context(row, &keyset, Scope::new(8u64)).await;
    assert!(matches!(other, Err(Error::Aead)), "{:?}", other.err());
}

/// Repeated parts append in order, and opening needs both.
#[tokio::test]
async fn a_second_part_appends_to_the_first() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let parts = || DeclaredContext::from(1u64).with(7u64);
    let (((email, _), _), _) = keyset.run(hand_composed(), &user(), parts()).await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        [
            "((users/email)/1u64)/7u64",
            "((users/age)/1u64)/7u64",
            "((users/notes)/1u64)/7u64"
        ]
    );
    let back: Result<String, _> = cipher
        .run_decryption(open(email.ciphertext, extended("email", parts())))
        .await;
    assert!(back.is_ok(), "{back:?}");

    // The second part alone does not open it: the first part is needed.
    let (((email, _), _), _) = keyset.run(hand_composed(), &user(), parts()).await.unwrap();
    let last_alone: Result<String, _> = cipher
        .run_decryption(open(
            email.ciphertext,
            extended("email", DeclaredContext::from(7u64)),
        ))
        .await;
    assert!(matches!(last_alone, Err(Error::Aead)), "{last_alone:?}");
}

/// An extension reaches the write, the query and the open of one value:
/// the data key is asked for under the extended label, a term matches only
/// under the same extension, and the value opens only with it.
#[tokio::test]
async fn one_value_extended_on_write_needs_the_extension_to_query_and_open() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let label = || NonEmpty::from(Label::parse("users/age").unwrap());
    let write = || {
        keyset.run(
            indexed::<u32, _, Borrowed, _>(Equality).under(label()),
            &34u32,
            DeclaredContext::from(7u64),
        )
    };

    let out = write().await.unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["(users/age)/7u64"]);

    let query = |parts: Option<u64>| {
        keyset.run(
            equality::<u32, _, Borrowed>().under(label()),
            &34u32,
            parts.map_or_else(DeclaredContext::default, DeclaredContext::from),
        )
    };
    assert_eq!(query(Some(7)).await.unwrap(), out.terms);
    assert_ne!(query(None).await.unwrap(), out.terms);
    assert_ne!(query(Some(8)).await.unwrap(), out.terms);

    let opening = |sealed: Encrypted<EqualityTerm>, parts: DeclaredContext| {
        cipher.run_decryption(open::<u32, _>(sealed.ciphertext, parts.under(label())))
    };
    let back = opening(out, DeclaredContext::from(7u64)).await.unwrap();
    assert_eq!(back, 34);
    let unextended = opening(write().await.unwrap(), DeclaredContext::default()).await;
    assert!(matches!(unextended, Err(Error::Aead)), "{unextended:?}");
    let other = opening(write().await.unwrap(), DeclaredContext::from(8u64)).await;
    assert!(matches!(other, Err(Error::Aead)), "{other:?}");
}

#[tokio::test]
async fn a_query_extended_like_the_write_matches_it() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let row: TenantUser = user()
        .encrypt_into_with_context(&keyset, Scope::new(7u64))
        .await
        .unwrap();
    let query = |tenant: u64| {
        TenantUser::EMAIL
            .eq("bob@example.com")
            .scope(Scope::new(tenant))
            .encrypt(&keyset)
    };
    assert_eq!(query(7).await.unwrap(), row.email.terms.0);
    assert_ne!(query(8).await.unwrap(), row.email.terms.0);
    // A query that names no tenant derives the term of a record that has
    // none, which is another term.
    let unextended = EncryptedUser::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(unextended, row.email.terms.0);
}

// --- One request for several operations ------------------------------------------

#[tokio::test]
async fn zip_settles_several_operations_in_one_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let user = user();
    let write = || user.clone().encrypt_into::<EncryptedUser, _>(&keyset);

    let (row, probe) = write()
        .zip(EncryptedUser::EMAIL.eq("bob@example.com").encrypt(&keyset))
        .await
        .unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1, "one generate call");
    assert_eq!(row.email.terms.0, probe);

    let ((a, b), c) = seal_doc(&keyset)
        .zip(write())
        .zip(User::decrypt_from(row, &keyset))
        .await
        .unwrap();
    assert_eq!(
        generates.load(Ordering::SeqCst),
        2,
        "one more generate call"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 1, "one retrieve call");
    assert_eq!(c.notes, "likes cheese");
    let (((_, _), opened), d) = seal_doc(&keyset)
        .zip(seal_doc(&keyset))
        .zip(String::decrypt_from_with_context(
            a,
            &keyset,
            nonempty!("docs"),
        ))
        .zip(write())
        .await
        .unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 3);
    assert_eq!(retrieves.load(Ordering::SeqCst), 2);
    assert_eq!(opened, "doc");
    assert_eq!(d.id, 42);
    let _ = b;
}

#[tokio::test]
async fn zip_runs_under_one_keyset_and_refuses_two() {
    let (cipher, generates, _) = counting_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let default = cipher.default_keyset();

    let (a, b) = seal_doc(&tenant).zip(seal_doc(&tenant)).await.unwrap();
    assert_eq!(leaf_keyset(&a), tenant.keyset_id());
    assert_eq!(leaf_keyset(&b), tenant.keyset_id());
    generates.store(0, Ordering::SeqCst);

    let refused = seal_doc(&tenant).zip(seal_doc(&default)).await;
    assert!(matches!(refused, Err(Error::KeysetMismatch { .. })));
    assert_eq!(
        generates.load(Ordering::SeqCst),
        0,
        "refused before any request"
    );
}

/// One operation that is refused fails the whole batch before any key is
/// requested, however valid the operations beside it are.
#[tokio::test]
async fn zip_refuses_a_failed_operation_beside_a_good_one_before_any_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let row: EncryptedUser = user().encrypt_into(&keyset).await.unwrap();
    generates.store(0, Ordering::SeqCst);
    let result = seal_doc(&keyset)
        .zip(User::decrypt_from(row, &keyset))
        .zip(
            // Text with no normal form: no term exists for it.
            EncryptedUser::EMAIL
                .eq("bob\u{0378}@example.com")
                .encrypt(&keyset),
        )
        .await;
    assert!(matches!(result, Err(Error::Term(_))));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_collection_runs_in_one_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let users = vec![user(), user(), user()];

    let rows: Vec<EncryptedUser> = users.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        generates.load(Ordering::SeqCst),
        1,
        "one generate for every row"
    );
    // A slice: each record's own description, merged into one request.
    let rows: Vec<EncryptedUser> = Pending::all(
        &keyset,
        users[..2]
            .iter()
            .map(|user| {
                keyset.run(
                    <EncryptedUser as EncryptTarget<User>>::encryption(),
                    user,
                    AllowsNoContext::omitted(),
                )
            })
            .collect(),
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(generates.load(Ordering::SeqCst), 2);

    let back = Vec::<User>::decrypt_from(rows, &keyset).await.unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        1,
        "one retrieve for every row"
    );
    assert_eq!(back[1].age, 34);

    let ages = vec![30u32, 31, 32];
    let context = || nonempty!("users").with("age");
    let written: Vec<Encrypted<EqualityTerm>> = ages
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(written.len(), 3);
    assert_eq!(generates.load(Ordering::SeqCst), 3);
    let back = Vec::<u32>::decrypt_from_with_context(written, &keyset, context())
        .await
        .unwrap();
    assert_eq!(back, ages);
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        2,
        "one retrieve for the Vec"
    );

    let written: Vec<Encrypted<EqualityTerm>> = ages
        .clone()
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let ciphertexts: Vec<StackCipherText> = written.into_iter().map(|e| e.ciphertext).collect();
    let back = Vec::<u32>::decrypt_from_with_context(ciphertexts, &keyset, context())
        .await
        .unwrap();
    assert_eq!(back, ages, "a Vec of bare ciphertexts opens too");
    assert_eq!(retrieves.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn nothing_touches_a_key_before_the_await() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let user = user();

    let dropped = user.clone().encrypt_into::<EncryptedUser, _>(&keyset);
    drop(dropped);
    assert_eq!(generates.load(Ordering::SeqCst), 0);

    // An operation yields its Pending synchronously: terms derived, key
    // requests queued, nothing sent until it is awaited.
    let pending = user.encrypt_into::<EncryptedUser, _>(&keyset);
    assert_eq!(generates.load(Ordering::SeqCst), 0, "prepared, not sent");
    let row = pending.await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    let pending = User::decrypt_from(row, &keyset);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    assert!(pending.await.is_ok());
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
}

/// A declaration is a description held by value: `KeysetCipher::run` runs
/// the encryption over a source, and `run_decryption` runs the decryption
/// a stored record describes.
#[tokio::test]
async fn a_declaration_is_an_encryption_and_a_decryption_held_by_value() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let encryption = <EncryptedUser as EncryptTarget<User>>::encryption();
    let row = keyset
        .run(encryption, &user(), AllowsNoContext::omitted())
        .await
        .unwrap();
    let decryption: Decryption<User, _> = row.decryption(AllowsNoContext::omitted());
    let back = keyset.run_decryption(decryption).await.unwrap();
    assert_eq!(back.id, 42);

    // The combinators describe a term alone the same way.
    let term = keyset
        .run(
            matching::<String, _, Borrowed, stack_encrypt::sem::DefaultMatch>()
                .under(nonempty!("users").with("email")),
            &user().email,
            DeclaredContext::default(),
        )
        .await
        .unwrap();
    let sealed: EncryptedUser = user().encrypt_into(&keyset).await.unwrap();
    assert_eq!(term.to_bytes(), sealed.email.terms.1.to_bytes());
}

// --- Keysets ---------------------------------------------------------------------

#[tokio::test]
async fn every_operation_honours_the_keyset_it_runs_through() {
    let cipher = stack_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let default = cipher.default_keyset();
    let id = tenant.keyset_id();
    assert_ne!(id, default.keyset_id());
    let user = user();

    let indexed: Encrypted<EqualityTerm> = 34u32
        .encrypt_into_with_context(&tenant, nonempty!("users").with("age"))
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&indexed.ciphertext), id);

    let (((_, _), notes), _) = tenant
        .run(hand_composed(), &user, DeclaredContext::default())
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&notes), id);

    let row: EncryptedUser = user.clone().encrypt_into(&tenant).await.unwrap();
    assert_eq!(leaf_keyset(&row.notes), id);

    // A term is keyed by the keyset's index key: a query under the tenant
    // matches the tenant's term, not the default keyset's.
    let query = |keyset| EncryptedUser::EMAIL.eq("bob@example.com").encrypt(keyset);
    assert_eq!(query(&tenant).await.unwrap(), row.email.terms.0);
    assert_ne!(query(&default).await.unwrap(), row.email.terms.0);

    // The record opens through its own keyset, and through the client,
    // which opens a leaf from any keyset. Another keyset refuses it.
    let row: EncryptedUser = user.clone().encrypt_into(&tenant).await.unwrap();
    assert_eq!(User::decrypt_from(row, &tenant).await.unwrap(), user);
    let row: EncryptedUser = user.clone().encrypt_into(&tenant).await.unwrap();
    assert_eq!(User::decrypt_from(row, &cipher).await.unwrap(), user);
    let row: EncryptedUser = user.clone().encrypt_into(&tenant).await.unwrap();
    let refused = User::decrypt_from(row, &default).await;
    assert!(
        matches!(refused, Err(Error::ForeignKeyset { .. })),
        "limited to a keyset, a leaf from another is refused: {refused:?}"
    );
}
