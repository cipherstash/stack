//! `#[derive(EncryptTarget)]` / `#[derive(DecryptSource)]`: a derived record
//! writes what its leaves write on their own. It has the same terms, it
//! decrypts through its one ciphertext, and it settles in one batched key
//! request. The tests also cover what only a derive makes cheap: sources
//! listed or left generic, structs encrypted field by field, and fields that
//! are not derived at all.
//!
//! The plaintext is passed by value (`value.encrypt_into(&keyset)`), so each
//! test clones or rebuilds the value it compares against.

mod common;

use std::sync::atomic::Ordering as AtomicOrdering;

use common::{counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::sem::Orderable;
use stack_encrypt::sem::{EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OreTerm, TermError};
use stack_encrypt::target::{
    AeadContext, CallerContext, DecryptSource, EncryptTarget, Encrypted, Encryption,
    RequiredContext, Scope,
};
use stack_encrypt::{
    nonempty, ContextPiece, DecryptField, DecryptFrom, Decryptable, EncryptInto, Error,
    IntoContext, Label, MaybeEmpty, NonEmpty, StackCipherText,
};
use zeroize::Zeroize;

// --- Records: every field from one plaintext, under one context -------------

/// The hand-written record in `target.rs`, derived: an encrypted `u32`
/// stored as its ciphertext plus an equality term and an ORE term.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

#[tokio::test]
async fn a_derived_record_is_the_hand_written_one() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let record: EncryptedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .unwrap();

    // Each term is what the leaf derives on its own, so query terms built
    // leaf-by-leaf find records encrypted as composites.
    let hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    let ob: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    assert_eq!(record.ob, ob);

    // And decryption opens the ciphertext field.
    let age = u32::decrypt_from_with_context(record, &cipher, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(age, 42);
}

/// No `plaintext`: one impl generic over it, accepting whatever every leaf
/// accepts — here any text type, since `MatchTerms` wants `AsRef<str>` — and
/// decrypting to whatever the ciphertext field opens to.
#[derive(EncryptTarget, DecryptSource)]
struct SearchableText {
    c: StackCipherText,
    hm: EqualityTerm,
    m: MatchTerms,
}

/// Tuple structs assign by index.
#[derive(EncryptTarget)]
struct Pair(StackCipherText, EqualityTerm);

/// A record may declare `'__k` itself: the declaration adds no keyset
/// lifetime. A target is `'static`, so a lifetime the record declares must
/// be too. Compiling is the test.
#[derive(EncryptTarget)]
#[stash(plaintext = u32)]
#[allow(dead_code)]
struct Borrowed<'__k: 'static> {
    c: StackCipherText,
    #[stash(default)]
    label: Option<&'__k str>,
}

/// The declaration's source lifetime steps aside for the record's own,
/// including when the first fallback name is also taken.
#[derive(EncryptTarget)]
#[stash(plaintext = u32)]
#[allow(dead_code)]
struct BorrowedSource<'__source: 'static, '__source_: 'static> {
    c: StackCipherText,
    #[stash(default)]
    label: Option<&'__source str>,
    #[stash(default)]
    other: Option<&'__source_ str>,
}

/// The record's own generics (and their bounds) are carried through, and the
/// where clause makes `Tagged<T>` accept exactly `T` — the ORE term is typed
/// by its source. A generic record's one-ciphertext check runs when the
/// record is first used rather than where it is defined.
#[derive(EncryptTarget, DecryptSource)]
struct Tagged<T: Orderable> {
    c: StackCipherText,
    ob: OreTerm<T>,
}

#[tokio::test]
async fn a_generic_plaintext_record_accepts_what_its_leaves_accept() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let record: SearchableText = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    let hm: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();
    let m: MatchTerms = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    assert_eq!(record.m, m);
    let name = String::decrypt_from_with_context(record, &cipher, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(name, "alice");

    let pair: Pair = "bob"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    let hm: EqualityTerm = "bob"
        .to_string()
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(pair.1, hm);
    let name = String::decrypt_from_with_context(pair.0, &cipher, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(name, "bob");

    let tagged: Tagged<u32> = 7u32
        .encrypt_into_with_context(&keyset, nonempty!("users/score"))
        .await
        .unwrap();
    let ob: OreTerm<u32> = 7u32
        .encrypt_into_with_context(&generator, nonempty!("users/score"))
        .await
        .unwrap();
    assert_eq!(tagged.ob, ob);
    let score = u32::decrypt_from_with_context(tagged, &cipher, nonempty!("users/score"))
        .await
        .unwrap();
    assert_eq!(score, 7);
}

/// Two ciphertexts in one record, both under the caller's context (every
/// output of a `plaintext` record shares it): the type system cannot pick,
/// so `#[stash(decrypt)]` does. Only marked fields are considered, and the
/// others need not be `Decryptable` at all.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct Doubled {
    #[stash(decrypt)]
    c: StackCipherText,
    shadow: StackCipherText,
}

/// Fields that are collections or optional follow their content: a record
/// of a `Vec<u32>` has one decryptable field, its `Vec<StackCipherText>`.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = Vec<u32>)]
struct Numbers {
    c: Vec<StackCipherText>,
    hm: Vec<EqualityTerm>,
}

#[tokio::test]
async fn decrypt_marks_the_field_when_the_types_cannot_choose() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let doubled: Doubled = 9u32
        .encrypt_into_with_context(&keyset, nonempty!("doubled"))
        .await
        .unwrap();
    let opened = u32::decrypt_from_with_context(doubled, &cipher, nonempty!("doubled"))
        .await
        .unwrap();
    assert_eq!(opened, 9);
    // The unmarked ciphertext is still a ciphertext, just not the record's:
    // a second, independent seal of the same value under the same context.
    let doubled: Doubled = 9u32
        .encrypt_into_with_context(&keyset, nonempty!("doubled"))
        .await
        .unwrap();
    let shadow = u32::decrypt_from_with_context(doubled.shadow, &cipher, nonempty!("doubled"))
        .await
        .unwrap();
    assert_eq!(shadow, 9);

    let numbers: Numbers = vec![1u32, 2, 3]
        .encrypt_into_with_context(&keyset, nonempty!("numbers"))
        .await
        .unwrap();
    assert_eq!(numbers.hm.len(), 3);
    let opened = Vec::<u32>::decrypt_from_with_context(numbers, &cipher, nonempty!("numbers"))
        .await
        .unwrap();
    assert_eq!(opened, vec![1, 2, 3]);
}

/// An index term type from outside this crate that does not say whether it
/// is recoverable: it implements `EncryptTarget` only, wrapping a term of
/// ours.
#[derive(PartialEq)]
struct OpaqueTerm(EqualityTerm);

impl<S: Zeroize> EncryptTarget<S> for OpaqueTerm
where
    EqualityTerm: EncryptTarget<S, ContextInput = RequiredContext<CallerContext>>,
{
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        <EqualityTerm as EncryptTarget<S>>::encryption().map(OpaqueTerm)
    }
}

/// The documented explicit-mode shape: `#[stash(decrypt)]` frees the *other*
/// field types from `Decryptable`, so the paired derive must compile with an
/// opaque field — including the `Decryptable` impl `EncryptTarget` emits.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct WithOpaque {
    #[stash(decrypt)]
    c: StackCipherText,
    o: OpaqueTerm,
}

/// And the marked record is decryptable outright, so it still nests in rows.
#[allow(clippy::assertions_on_constants)] // the constant is the point
const _: () = assert!(<WithOpaque as Decryptable>::DECRYPTABLE);

#[tokio::test]
async fn explicit_mode_supports_opaque_fields_in_the_paired_derive() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let record: WithOpaque = 5u32
        .encrypt_into_with_context(&keyset, nonempty!("opaque"))
        .await
        .unwrap();
    let hm: EqualityTerm = 5u32
        .encrypt_into_with_context(&generator, nonempty!("opaque"))
        .await
        .unwrap();
    assert!(record.o == OpaqueTerm(hm));

    let opened = u32::decrypt_from_with_context(record, &cipher, nonempty!("opaque"))
        .await
        .unwrap();
    assert_eq!(opened, 5);
}

/// A third-party field type that breaks the `DecryptField` contract:
/// `DECRYPTABLE` says decryption opens it, but `decryption_field` passes it
/// over anyway.
struct Lying;

impl Decryptable for Lying {
    const DECRYPTABLE: bool = true;
}

impl<P, Ctx> DecryptField<P, Ctx> for Lying {
    fn decryption_field<K: 'static>(
        self,
        _context: Ctx,
    ) -> Option<stack_encrypt::Decryption<P, K>> {
        None
    }
}

#[derive(DecryptSource)]
struct LyingRecord {
    l: Lying,
}

#[derive(Debug, PartialEq, Zeroize)]
struct Held {
    value: u32,
}

#[derive(DecryptSource)]
#[stash(struct = Held, scope = "held")]
struct LyingHeld {
    value: Lying,
}

#[tokio::test]
async fn a_broken_decrypt_field_contract_is_not_opened_never_a_panic() {
    let cipher = stack_cipher().await;

    // The compile-time check accepted `Lying` (its `DECRYPTABLE` is `true`),
    // so the broken contract only shows at decrypt time: `Error::NotOpened`
    // as a failed pending, for the record and for the row alike.
    let result =
        u32::decrypt_from_with_context(LyingRecord { l: Lying }, &cipher, nonempty!("l")).await;
    assert!(matches!(result, Err(Error::NotOpened)));

    let result = Held::decrypt_from(LyingHeld { value: Lying }, &cipher).await;
    assert!(matches!(result, Err(Error::NotOpened)));
}

/// Listed plaintexts: one impl each, and nothing else is accepted.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32, plaintext = String)]
struct EncryptedValue {
    c: StackCipherText,
    hm: EqualityTerm,
}

#[tokio::test]
async fn listed_plaintexts_each_get_their_own_impl() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let number: EncryptedValue = 7u32
        .encrypt_into_with_context(&keyset, nonempty!("t/n"))
        .await
        .unwrap();
    let text: EncryptedValue = "seven"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("t/t"))
        .await
        .unwrap();
    let hm: EqualityTerm = 7u32
        .encrypt_into_with_context(&keyset, nonempty!("t/n"))
        .await
        .unwrap();
    assert_eq!(number.hm, hm);

    let number = u32::decrypt_from_with_context(number, &cipher, nonempty!("t/n"))
        .await
        .unwrap();
    let text = String::decrypt_from_with_context(text, &cipher, nonempty!("t/t"))
        .await
        .unwrap();
    assert_eq!((number, text.as_str()), (7, "seven"));
}

/// A plain `IntoContext` type, declared through `AeadContext`: enough to
/// seal, not to derive a term. `WorkspaceId` in `cts-common` is the
/// production shape.
#[derive(Clone, Debug, PartialEq)]
struct Tenant(String);
impl MaybeEmpty for Tenant {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl<'a> IntoContext<'a> for Tenant {
    fn into_context(self) -> ContextPiece<'a> {
        self.0.into_context()
    }
}

/// Ciphertext only, so it declares the ciphertext operation's own context
/// type rather than the default `CallerContext`, which would demand a PRF
/// encoding no field here uses.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedName {
    c: StackCipherText,
}

fn tenant() -> NonEmpty<Tenant> {
    NonEmpty::new(Tenant("acme".into())).unwrap()
}

#[tokio::test]
async fn a_ciphertext_only_record_accepts_an_aead_only_context_like_the_leaf_does() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let name = "alice".to_owned();

    // The derived record and the canonical leaf accept the same context
    // and produce interchangeable ciphertext: each opens the other's.
    let record: SealedName = name
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let opened: String = cipher.decrypt(record.c, tenant()).await.unwrap();
    assert_eq!(opened, name);

    let leaf = keyset.encrypt_tree(name.clone(), tenant()).await.unwrap();
    let opened = String::decrypt_from_with_context(SealedName { c: leaf }, &cipher, tenant())
        .await
        .unwrap();
    assert_eq!(opened, name);

    // Bound to the context like any other leaf.
    let record: SealedName = name
        .clone()
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let other = NonEmpty::new(Tenant("other".into())).unwrap();
    let result = String::decrypt_from_with_context(record, &cipher, other).await;
    assert!(matches!(result, Err(Error::Aead)), "{result:?}");
}

/// A match configuration whose options fail the scheme's bounds, so its
/// leaf fails during the synchronous build.
struct TooManyHashes;
impl MatchConfig for TooManyHashes {
    fn options() -> MatchOptions {
        MatchOptions {
            k: 17,
            ..Default::default()
        }
    }
}

#[derive(EncryptTarget, DecryptSource)]
struct BadlyIndexedText {
    c: StackCipherText,
    m: MatchTerms<TooManyHashes>,
}

#[tokio::test]
async fn a_failed_field_fails_the_derived_record_before_any_io() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();

    // Invalid match options fail that leaf during the synchronous build;
    // the derived record is the zip of its fields, so it fails the same way
    // and never mints the data key its ciphertext field would have wanted.
    let result: Result<BadlyIndexedText, _> = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await;
    assert!(matches!(
        result,
        Err(Error::Term(TermError::InvalidOptions(_)))
    ));
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);

    // Text with no match tokens is not a failure: the leaf is the empty
    // filter, and the record seals as any other.
    let stored: SearchableText = String::new()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    assert!(stored.m.positions().is_empty());
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);
}

// --- Structs: each field from one field of the plaintext, under its own context

// `Zeroize` is required: the conversion takes the struct by value and wipes
// each field it seals, and a column of these decrypts through the wiping
// collection path, which wipes the rows recovered before a late failure.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
struct User {
    age: u32,
    email: String,
}

/// A struct encrypted field by field: every field is derived from the
/// plaintext field of its own name, under the context `"<context>/<field>"`
/// — `"user/age"`, `"user/email"` — with no attribute on the field. The
/// prefix names the stored data, explicitly: it is part of its identity, so
/// it is never inferred from the type's name. `from` is the override for a
/// field name that differs; the context then follows the plaintext field.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "user")]
struct EncryptedUser {
    /// A record inside a struct: recursion, not a second mechanism.
    age: EncryptedAge,
    /// A ciphertext with its search terms beside it is one field: one
    /// output per plaintext field. Decryption opens its ciphertext.
    email: Encrypted<(EqualityTerm, MatchTerms)>,
    /// Not derived: filled in, never encrypted.
    #[stash(default = 3)]
    version: u8,
}

fn user() -> User {
    User {
        age: 42,
        email: "alice@example.com".to_string(),
    }
}

#[tokio::test]
async fn a_struct_is_one_batched_call_and_rebuilds_its_plaintext() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    // Every field has its own context, so the struct needs none from the
    // caller: the context-free forms are the whole call, both ways.
    let row: EncryptedUser = user().encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        1,
        "a two-ciphertext struct must be ONE generate_keys call"
    );
    assert_eq!(row.version, 3);

    // Each field's terms are what a query site derives under the field's
    // inferred context: the prefix and the plaintext field's name.
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("user").with("age"))
        .await
        .unwrap();
    assert_eq!(row.age.hm, age_hm);
    let email_hm: EqualityTerm = user()
        .email
        .encrypt_into_with_context(&generator, nonempty!("user").with("email"))
        .await
        .unwrap();
    let email_match: MatchTerms = user()
        .email
        .encrypt_into_with_context(&generator, nonempty!("user").with("email"))
        .await
        .unwrap();
    assert_eq!(row.email.terms, (email_hm, email_match));
    // The field's marker is that query site: it derives the stored term.
    let by_marker = EncryptedUser::EMAIL
        .eq(user().email)
        .encrypt(&generator)
        .await
        .unwrap();
    assert_eq!(by_marker, row.email.terms.0);

    // Decryption rebuilds the plaintext field by field: one batched call.
    let recovered = User::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, user());
    assert_eq!(
        retrieves.load(AtomicOrdering::SeqCst),
        1,
        "opening a two-ciphertext struct must be ONE retrieve_keys call"
    );
}

#[tokio::test]
async fn a_column_of_structs_is_still_one_call_each_way() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();

    let users: Vec<User> = (0..4)
        .map(|i| User {
            age: 30 + i,
            email: format!("user{i}@example.com"),
        })
        .collect();

    let rows: Vec<EncryptedUser> = users.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    let recovered = Vec::<User>::decrypt_from(rows, &cipher).await.unwrap();
    assert_eq!(recovered, users);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);
}

/// The same struct, with a part the caller supplies on every call. A
/// `struct` record takes no context it does not declare, so the row's id is
/// declared as a scope.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "user", scope(id: u64))]
struct EncryptedUserOfRow {
    age: EncryptedAge,
    email: Encrypted<(EqualityTerm, MatchTerms)>,
}

#[tokio::test]
async fn a_struct_extends_its_contexts_with_the_callers() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    // The caller's scope — the record's id — extends every inferred context:
    // `age` is derived under `("user/age", 7u64)`, still in one batched
    // call, and a query site probes it under the same pair.
    let row: EncryptedUserOfRow = user()
        .encrypt_into_with_context(&keyset, Scope::new(7u64))
        .await
        .unwrap();
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("user").with("age").with(7u64))
        .await
        .unwrap();
    assert_eq!(row.age.hm, age_hm);
    let unextended: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("user").with("age"))
        .await
        .unwrap();
    assert_ne!(row.age.hm, unextended);

    // Opens under the same scope, in one call — and under no other.
    let recovered = User::decrypt_from_with_context(row, &cipher, Scope::new(7u64))
        .await
        .unwrap();
    assert_eq!(recovered, user());
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);

    let row: EncryptedUserOfRow = user()
        .encrypt_into_with_context(&keyset, Scope::new(7u64))
        .await
        .unwrap();
    // The fake key source ignores descriptors, so the AEAD is what refuses
    // a wrong context here. ZeroKMS refuses the key retrieval itself first
    // (`Error::Kms`).
    let other_row = User::decrypt_from_with_context(row, &cipher, Scope::new(8u64)).await;
    assert!(matches!(other_row, Err(Error::Aead)));
}

#[tokio::test]
async fn a_struct_field_opened_under_the_wrong_context_fails() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let row: EncryptedUser = user().encrypt_into(&keyset).await.unwrap();
    // The literal contexts are baked into the impl, so a transplanted field
    // is caught exactly as for a leaf: by the AAD against the fake key
    // source, by ZeroKMS's descriptor check (`Error::Kms`) before that in
    // production.
    let transplanted =
        u32::decrypt_from_with_context(row.age.c, &cipher, nonempty!("user").with("height")).await;
    assert!(matches!(transplanted, Err(Error::Aead)));
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
struct Account {
    user: User,
    plan: String,
}

/// A struct nesting a struct: the record-typed field is an ordinary field,
/// derived under the inferred pair `("accounts", "user")` like any other,
/// and the inner struct's own fields sit under that: their contexts are
/// extended by it, as by any context the inner struct is handed.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    user: EncryptedUser,
    plan: StackCipherText,
}

/// The same nesting, with a scope the caller supplies on the outer record.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, scope = "accounts", scope(id: u64))]
struct EncryptedAccountOfRow {
    user: EncryptedUser,
    plan: StackCipherText,
}

fn account() -> Account {
    Account {
        user: user(),
        plan: "pro".to_string(),
    }
}

#[tokio::test]
async fn a_struct_nests_in_a_struct_as_an_ordinary_field() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let row: EncryptedAccount = account().encrypt_into(&keyset).await.unwrap();
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    // The inner struct's fields are under their own contexts, extended by
    // the outer field's pair.
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(
            &generator,
            nonempty!("user")
                .with("age")
                .with(nonempty!("accounts").with("user")),
        )
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);

    let recovered = Account::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, account());
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);

    // The outer's plan is under the inferred `"accounts/plan"`. Decrypting
    // the row consumed it, so mint a fresh one to open the field alone.
    let row: EncryptedAccount = account().encrypt_into(&keyset).await.unwrap();
    let plan =
        String::decrypt_from_with_context(row.plan, &cipher, nonempty!("accounts").with("plan"))
            .await
            .unwrap();
    assert_eq!(plan, "pro");

    // A scope the caller supplies extends the outer field's pair, which the
    // inner struct composes with its own contexts: the inner `age` is under
    // `("user/age", ("accounts/user", id))`, the outer `plan` under
    // `("accounts/plan", id)`.
    let row: EncryptedAccountOfRow = account()
        .encrypt_into_with_context(&keyset, Scope::new(9u64))
        .await
        .unwrap();
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(
            &generator,
            nonempty!("user")
                .with("age")
                .with(nonempty!("accounts").with("user").with(9u64)),
        )
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);
    let plan = String::decrypt_from_with_context(
        row.plan,
        &cipher,
        nonempty!("accounts").with("plan").with(9u64),
    )
    .await
    .unwrap();
    assert_eq!(plan, "pro");

    // The whole record opens under the same id: the decrypt side hands the
    // inner record the outer field's pair extended by the id, as the
    // encrypt side did.
    let row: EncryptedAccountOfRow = account()
        .encrypt_into_with_context(&keyset, Scope::new(9u64))
        .await
        .unwrap();
    let recovered = Account::decrypt_from_with_context(row, &cipher, Scope::new(9u64))
        .await
        .unwrap();
    assert_eq!(recovered, account());

    // And not under another. The fake key source ignores descriptors, so the
    // AEAD refuses; ZeroKMS would refuse the key retrieval first
    // (`Error::Kms`).
    let row: EncryptedAccountOfRow = account()
        .encrypt_into_with_context(&keyset, Scope::new(9u64))
        .await
        .unwrap();
    let other = Account::decrypt_from_with_context(row, &cipher, Scope::new(8u64)).await;
    assert!(matches!(other, Err(Error::Aead)), "{other:?}");
}

/// A tuple-struct plaintext is reached by index — inferred for a tuple
/// struct, `from = 0` when the encrypted struct has named fields. An index
/// is no name for a label segment (it begins with a digit, which a
/// descriptor reserves), so each field under `struct = ..` names its segment
/// with `identity = ".."`, keyed under `("reading", "<identity>")`; the
/// derive refuses one that does not (`tests/ui`).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
struct Reading(u32, String);

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Reading, scope = "reading")]
struct EncryptedReading(
    #[stash(identity = "value")] EncryptedAge,
    #[stash(identity = "unit")] StackCipherText,
);

/// The same with named fields: `from` by index, and the segment given.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Reading, scope = "reading")]
struct NamedReading {
    #[stash(from = 0, identity = "value")]
    value: EncryptedAge,
    #[stash(from = 1, identity = "unit")]
    unit: StackCipherText,
}

#[tokio::test]
async fn a_tuple_plaintext_is_reached_and_rebuilt_by_index() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let reading = Reading(21, "celsius".into());
    let row: EncryptedReading = reading.clone().encrypt_into(&keyset).await.unwrap();

    let hm: EqualityTerm = 21u32
        .encrypt_into_with_context(&generator, nonempty!("reading").with("value"))
        .await
        .unwrap();
    assert_eq!(row.0.hm, hm);

    let recovered = Reading::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, reading);

    let named: NamedReading = reading.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(named.value.hm, hm, "from = 0 with the same identity");
    let unit =
        String::decrypt_from_with_context(named.unit, &cipher, nonempty!("reading").with("unit"))
            .await
            .unwrap();
    assert_eq!(unit, "celsius");
}

// --- A field handed a context converts it into what its type declares -------

/// A `plaintext` record wrapping a struct record that carries contexts of
/// its own: the caller's context reaches the inner record as it is, and
/// extends its contexts, `("user/age", "wrapped")`. The derive is told
/// nothing about the inner record's context type.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = User)]
struct WrappedUser {
    user: EncryptedUser,
}

#[tokio::test]
async fn a_plaintext_record_field_may_be_a_record_with_declared_contexts() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let row: WrappedUser = user()
        .encrypt_into_with_context(&keyset, nonempty!("wrapped"))
        .await
        .unwrap();
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(
            &generator,
            nonempty!("user").with("age").with(nonempty!("wrapped")),
        )
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);

    let recovered = User::decrypt_from_with_context(row, &cipher, nonempty!("wrapped"))
        .await
        .unwrap();
    assert_eq!(recovered, user());
}

// --- A record that stores its context ----------------------------------------

/// `context_field`: the record stores the context it was sealed under, and
/// opening checks it against the context the caller expects.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct ScopedEmail {
    #[stash(context_field)]
    scope: Label,
    c: StackCipherText,
    hm: EqualityTerm,
}

fn scope() -> NonEmpty<Label> {
    NonEmpty::from(Label::parse("tenants/acme/email").unwrap())
}

fn email() -> String {
    "bob@example.com".to_string()
}

#[tokio::test]
async fn a_context_field_record_is_sealed_under_the_context_it_stores() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let derived: ScopedEmail = email()
        .encrypt_into_with_context(&keyset, scope())
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["tenants/acme/email"],
        "the field is sealed under the context the derive is handed"
    );
    assert_eq!(derived.scope, scope().into_inner());
    // The term is the leaf's under the same context.
    let hm: EqualityTerm = email()
        .encrypt_into_with_context(&keyset, scope())
        .await
        .unwrap();
    assert_eq!(derived.hm, hm);

    // A record rebuilt from its stored parts opens under the context the
    // caller expects, and the leaf's ciphertext opens through the record.
    let leaf: StackCipherText = email()
        .encrypt_into_with_context(&keyset, scope())
        .await
        .unwrap();
    let opened = String::decrypt_from_with_context(
        ScopedEmail {
            scope: scope().into_inner(),
            c: leaf,
            hm,
        },
        &cipher,
        scope(),
    )
    .await
    .unwrap();
    assert_eq!(opened, email());
    let opened = String::decrypt_from_with_context(derived, &cipher, scope())
        .await
        .unwrap();
    assert_eq!(opened, email());
}

#[tokio::test]
async fn a_context_field_record_refuses_a_mismatched_expected_context_before_any_key_request() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();

    let derived: ScopedEmail = email()
        .encrypt_into_with_context(&keyset, scope())
        .await
        .unwrap();
    let other = NonEmpty::from(Label::parse("tenants/globex/email").unwrap());
    let refused = String::decrypt_from_with_context(derived, &cipher, other).await;
    assert!(
        matches!(refused, Err(Error::ContextMismatch { .. })),
        "{refused:?}"
    );
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 0);
}
