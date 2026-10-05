//! `#[derive(EncryptFrom)]` / `#[derive(DecryptInto)]`: the derived impls are the
//! hand-written composite in `target.rs`, emitted — same terms, same decrypt
//! mirror, same one-batched-call settlement — plus what only a derive makes
//! cheap: sources listed or left generic, structs encrypted field by field,
//! and fields that are not derived at all.

mod common;

use std::sync::atomic::Ordering as AtomicOrdering;

use cllw_ore::CllwOreEncrypt;
use common::{counting_cipher, stack_cipher};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreTerm};
use stack_encrypt::target::{AeadContext, DecryptFrom, EncryptInto};
use stack_encrypt::{
    nonempty, ContextPiece, DecryptField, DecryptInto, Decryptable, EncryptFrom, Error,
    IntoContext, MaybeEmpty, NonEmpty, StackCipherText,
};

// --- Records: every field from one plaintext, under one context -------------

/// The hand-written record in `target.rs`, derived: an encrypted `u32`
/// stored as its ciphertext plus an equality term and an ORE term.
#[derive(EncryptFrom, DecryptInto)]
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

    // And the decrypt mirror opens the ciphertext field.
    let age: u32 = record
        .decrypt_into(&cipher, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(age, 42);
}

/// No `plaintext`: one impl generic over it, accepting whatever every leaf
/// accepts — here any text type, since `MatchTerms` wants `AsRef<str>` — and
/// decrypting to whatever the ciphertext field opens to.
#[derive(EncryptFrom, DecryptInto)]
struct SearchableText {
    c: StackCipherText,
    hm: EqualityTerm,
    m: MatchTerms,
}

/// Tuple structs assign by index.
#[derive(EncryptFrom)]
struct Pair(StackCipherText, EqualityTerm);

/// A record may declare `'__k` itself; the declaration API no longer adds
/// a keyset lifetime. Compiling is the test.
#[derive(EncryptFrom)]
#[stash(plaintext = u32)]
#[allow(dead_code)]
struct Borrowed<'__k> {
    c: StackCipherText,
    #[stash(default)]
    label: Option<&'__k str>,
}

/// The declaration's source lifetime steps aside for the record's own,
/// including when the first fallback name is also taken.
#[derive(EncryptFrom)]
#[stash(plaintext = u32)]
#[allow(dead_code)]
struct BorrowedSource<'__source, '__source_> {
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
#[derive(EncryptFrom, DecryptInto)]
struct Tagged<T: CllwOreEncrypt> {
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
    let name: String = record
        .decrypt_into(&cipher, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(name, "alice");

    let pair: Pair = "bob"
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    let hm: EqualityTerm = "bob"
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(pair.1, hm);
    let name: String = pair
        .0
        .decrypt_into(&cipher, nonempty!("users/name"))
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
    let score: u32 = tagged
        .decrypt_into(&cipher, nonempty!("users/score"))
        .await
        .unwrap();
    assert_eq!(score, 7);
}

/// Two ciphertexts in one record: the type system cannot pick, so
/// `#[stash(decrypt)]` does. Only marked fields are considered, and the
/// others need not be `Decryptable` at all.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Doubled {
    #[stash(decrypt)]
    c: StackCipherText,
    #[stash(context = "doubled/shadow")]
    shadow: StackCipherText,
}

/// Fields that are collections or optional follow their content: a record
/// of a `Vec<u32>` has one decryptable field, its `Vec<StackCipherText>`.
#[derive(EncryptFrom, DecryptInto)]
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
    let opened: u32 = doubled
        .decrypt_into(&cipher, nonempty!("doubled"))
        .await
        .unwrap();
    assert_eq!(opened, 9);
    // The unmarked ciphertext is still a ciphertext, just not the record's —
    // and its literal context is extended by the caller's like any other:
    // sealed under `("doubled/shadow", "doubled")`.
    let doubled: Doubled = 9u32
        .encrypt_into_with_context(&keyset, nonempty!("doubled"))
        .await
        .unwrap();
    let shadow: u32 = doubled
        .shadow
        .decrypt_into(
            &cipher,
            nonempty!("doubled/shadow").with(nonempty!("doubled")),
        )
        .await
        .unwrap();
    assert_eq!(shadow, 9);

    let numbers: Numbers = vec![1u32, 2, 3]
        .encrypt_into_with_context(&keyset, nonempty!("numbers"))
        .await
        .unwrap();
    assert_eq!(numbers.hm.len(), 3);
    let opened: Vec<u32> = numbers
        .decrypt_into(&cipher, nonempty!("numbers"))
        .await
        .unwrap();
    assert_eq!(opened, vec![1, 2, 3]);
}

/// An index term type from outside this crate that predates `Decryptable`:
/// it implements `EncryptFrom` only, wrapping a term of ours.
#[derive(PartialEq)]
struct OpaqueTerm(EqualityTerm);

impl<S> EncryptFrom<S> for OpaqueTerm
where
    EqualityTerm: EncryptFrom<S>,
{
    type Context = <EqualityTerm as EncryptFrom<S>>::Context;
    fn encryption<'s, K: 'static>() -> stack_encrypt::Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        <EqualityTerm as EncryptFrom<S>>::encryption().map(OpaqueTerm)
    }
}

/// The documented explicit-mode shape: `#[stash(decrypt)]` frees the *other*
/// field types from `Decryptable`, so the paired derive must compile with an
/// opaque field — including the `Decryptable` impl `EncryptFrom` emits.
#[derive(EncryptFrom, DecryptInto)]
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

    let opened: u32 = record
        .decrypt_into(&cipher, nonempty!("opaque"))
        .await
        .unwrap();
    assert_eq!(opened, 5);
}

/// A third-party field type that breaks the `DecryptField` contract:
/// `DECRYPTABLE` says decryption opens it, but `decrypt_field` passes it
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

#[derive(DecryptInto)]
struct LyingRecord {
    l: Lying,
}

#[derive(Debug, PartialEq)]
struct Held {
    value: u32,
}

#[derive(DecryptInto)]
#[stash(struct = Held, context = "held")]
struct LyingHeld {
    value: Lying,
}

#[tokio::test]
async fn a_broken_decrypt_field_contract_is_not_opened_never_a_panic() {
    let cipher = stack_cipher().await;

    // The compile-time check accepted `Lying` (its `DECRYPTABLE` is `true`),
    // so the broken contract only shows at decrypt time: `Error::NotOpened`
    // as a failed pending, for the record and for the row alike.
    let result: Result<u32, _> = LyingRecord { l: Lying }
        .decrypt_into(&cipher, nonempty!("l"))
        .await;
    assert!(matches!(result, Err(Error::NotOpened)));

    let result: Result<Held, _> = LyingHeld { value: Lying }.decrypt_into(&cipher, ()).await;
    assert!(matches!(result, Err(Error::NotOpened)));
}

/// Listed plaintexts: one impl each, and nothing else is accepted.
#[derive(EncryptFrom, DecryptInto)]
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

    let number: u32 = number
        .decrypt_into(&cipher, nonempty!("t/n"))
        .await
        .unwrap();
    let text: String = text.decrypt_into(&cipher, nonempty!("t/t")).await.unwrap();
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
#[derive(EncryptFrom, DecryptInto)]
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
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let opened: String = cipher.decrypt(record.c, tenant()).await.unwrap();
    assert_eq!(opened, name);

    let leaf = keyset.encrypt(name.clone(), tenant()).await.unwrap();
    let opened: String = SealedName { c: leaf }
        .decrypt_into(&cipher, tenant())
        .await
        .unwrap();
    assert_eq!(opened, name);

    // Bound to the context like any other leaf.
    let record: SealedName = name
        .encrypt_into_with_context(&keyset, tenant())
        .await
        .unwrap();
    let other = NonEmpty::new(Tenant("other".into())).unwrap();
    let result: Result<String, _> = record.decrypt_into(&cipher, other).await;
    assert!(matches!(result, Err(Error::Aead)), "{result:?}");
}

#[tokio::test]
async fn a_failed_field_fails_the_derived_record_before_any_io() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();

    // Text that yields no match tokens fails that leaf during the
    // synchronous build; the derived record is the zip of its fields, so it
    // fails the same way and never mints the data key its ciphertext field
    // would have wanted.
    let result: Result<SearchableText, _> = String::new()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await;
    assert!(matches!(result, Err(Error::Term(_))));
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

// --- Structs: each field from one field of the plaintext, under its own context

#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "user")]
struct EncryptedUser {
    /// A record inside a struct: recursion, not a second mechanism.
    age: EncryptedAge,
    email: StackCipherText,
    /// A second field from the same plaintext field — a term alongside the
    /// ciphertext, not opened on decrypt.
    #[stash(from = email)]
    email_eq: EqualityTerm,
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
    assert_eq!(row.email_eq, email_hm);

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

    let rows: Vec<EncryptedUser> = users.encrypt_into(&keyset).await.unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    let recovered = Vec::<User>::decrypt_from(rows, &cipher).await.unwrap();
    assert_eq!(recovered, users);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test]
async fn a_struct_extends_its_contexts_with_the_callers() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    // The caller's context — the record's id — extends every inferred one:
    // `age` is derived under `("user/age", 7u64)`, still in one batched
    // call, and a query site probes it under the same pair.
    let row: EncryptedUser = user()
        .encrypt_into_with_context(&keyset, 7u64)
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

    // Opens under the same extension, in one call — and under no other.
    let recovered = User::decrypt_from_with_context(row, &cipher, 7u64)
        .await
        .unwrap();
    assert_eq!(recovered, user());
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);

    let row: EncryptedUser = user()
        .encrypt_into_with_context(&keyset, 7u64)
        .await
        .unwrap();
    // The fake key source ignores descriptors, so the AEAD is what refuses
    // a wrong context here. ZeroKMS refuses the key retrieval itself first
    // (`Error::Kms`) — `examples/encrypted_record.rs` shows that live.
    let other_row = User::decrypt_from_with_context(row, &cipher, 8u64).await;
    assert!(matches!(other_row, Err(Error::Aead)));
    let row: EncryptedUser = user()
        .encrypt_into_with_context(&keyset, 7u64)
        .await
        .unwrap();
    let no_row = User::decrypt_from(row, &cipher).await;
    assert!(matches!(no_row, Err(Error::Aead)));

    // Any context does: a string, a pair, an `Option`.
    let row: EncryptedUser = user()
        .encrypt_into_with_context(&keyset, nonempty!("tenant/acme"))
        .await
        .unwrap();
    let recovered = User::decrypt_from_with_context(row, &cipher, nonempty!("tenant/acme"))
        .await
        .unwrap();
    assert_eq!(recovered, user());
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
    let transplanted: Result<u32, _> = row
        .age
        .c
        .decrypt_into(&cipher, nonempty!("user").with("height"))
        .await;
    assert!(matches!(transplanted, Err(Error::Aead)));
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Account {
    user: User,
    plan: String,
}

/// A struct nesting a struct: `#[stash(nested)]` opts the field out of the
/// inferred context — the inner struct carries its own — so it is handed
/// the caller's context as it is, which the inner struct composes with them.
#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = Account, context = "accounts")]
struct EncryptedAccount {
    #[stash(nested)]
    user: EncryptedUser,
    plan: StackCipherText,
}

#[tokio::test]
async fn a_struct_nests_in_a_struct_via_nested() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let account = Account {
        user: user(),
        plan: "pro".to_string(),
    };
    let row: EncryptedAccount = account.encrypt_into(&keyset).await.unwrap();
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    // The inner struct's fields are still under their own contexts.
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("user").with("age"))
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);

    let recovered = Account::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, account);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);

    // The outer's plan is under the inferred `"accounts/plan"`. Decrypting
    // the row consumed it, so mint a fresh one to open the field alone.
    let row: EncryptedAccount = account.encrypt_into(&keyset).await.unwrap();
    let plan: String = row
        .plan
        .decrypt_into(&cipher, nonempty!("accounts").with("plan"))
        .await
        .unwrap();
    assert_eq!(plan, "pro");

    // An extension reaches the nested struct unchanged and is composed with
    // its own contexts there: the inner `age` is under `("user/age", id)`,
    // the outer `plan` under `("accounts/plan", id)`.
    let row: EncryptedAccount = account
        .encrypt_into_with_context(&keyset, 9u64)
        .await
        .unwrap();
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("user").with("age").with(9u64))
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);
    let plan: String = row
        .plan
        .decrypt_into(&cipher, nonempty!("accounts").with("plan").with(9u64))
        .await
        .unwrap();
    assert_eq!(plan, "pro");
}

/// A tuple-struct plaintext is reached by index — inferred for a tuple
/// struct, `from = 0` when the encrypted struct has named fields. An index
/// is no name for a label segment (it begins with a digit, which a
/// descriptor reserves), so each field under `struct = ..` names its segment
/// with `identity = ".."`, keyed under `("reading", "<identity>")`; the
/// derive refuses one that does not (`tests/ui`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reading(u32, String);

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = Reading, context = "reading")]
struct EncryptedReading(
    #[stash(identity = "value")] EncryptedAge,
    #[stash(identity = "unit")] StackCipherText,
);

/// The same with named fields: `from` by index, and the segment given.
#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = Reading, context = "reading")]
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
    let row: EncryptedReading = reading.encrypt_into(&keyset).await.unwrap();

    let hm: EqualityTerm = 21u32
        .encrypt_into_with_context(&generator, nonempty!("reading").with("value"))
        .await
        .unwrap();
    assert_eq!(row.0.hm, hm);

    let recovered = Reading::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, reading);

    let named: NamedReading = reading.encrypt_into(&keyset).await.unwrap();
    assert_eq!(named.value.hm, hm, "from = 0 with the same identity");
    let unit: String = named
        .unit
        .decrypt_into(&cipher, nonempty!("reading").with("unit"))
        .await
        .unwrap();
    assert_eq!(unit, "celsius");
}

// --- A field handed a context converts it into what its type declares -------

/// A record with a context of its own wrapping a struct record that carries
/// its own: the literal gives the whole subtree its context, and the inner
/// record's own contexts are extended by it — `("user/age", "wrapped")`.
/// The derive is told nothing about the inner record's context type.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = User)]
struct WrappedUser {
    #[stash(context = "wrapped")]
    user: EncryptedUser,
}

#[tokio::test]
async fn a_field_with_its_own_context_may_be_a_record_with_declared_contexts() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = stack_cipher().await;
    let generator = generator.default_keyset();

    let row: WrappedUser = user().encrypt_into(&keyset).await.unwrap();
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(
            &generator,
            nonempty!("user").with("age").with(nonempty!("wrapped")),
        )
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);

    let recovered = User::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, user());
}

/// A record whose one field pins a literal context: needs nothing from the
/// caller, and a caller's context extends the literal.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct PinnedAge {
    #[stash(context = "legacy/age")]
    c: StackCipherText,
}

/// A record mixing a leaf with a context of its own and a bare record whose
/// fields declare theirs: the caller's context is required, since the bare
/// field needs it; the leaf's literal is extended by it; and the record is
/// handed it as it is and composes it with its own.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct AuditedAge {
    #[stash(context = "audit/age", decrypt)]
    audit: StackCipherText,
    age: PinnedAge,
}

#[tokio::test]
async fn a_bare_record_field_takes_the_callers_context_beside_a_leaf_with_its_own() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let row: AuditedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("tenant"))
        .await
        .unwrap();
    // The leaf: its own literal, extended by the caller's.
    let audit: u32 = row
        .audit
        .decrypt_into(&cipher, nonempty!("audit/age").with(nonempty!("tenant")))
        .await
        .unwrap();
    assert_eq!(audit, 42);
    // The record: handed the caller's as it is, which extends its own.
    let age: u32 = row
        .age
        .c
        .decrypt_into(&cipher, nonempty!("legacy/age").with(nonempty!("tenant")))
        .await
        .unwrap();
    assert_eq!(age, 42);

    // And the record as a whole opens under the caller's context.
    let row: AuditedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("tenant"))
        .await
        .unwrap();
    let opened: u32 = row
        .decrypt_into(&cipher, nonempty!("tenant"))
        .await
        .unwrap();
    assert_eq!(opened, 42);
}
