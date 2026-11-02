//! Owned record declarations: `#[derive(EncryptTarget, DecryptSource)]` over
//! a plaintext struct, with passthrough fields, nested records, renamed
//! source fields, a stored context, and one batch per collection. The
//! public mixed-record and searchable-record programs run here against the
//! fake key source. No service credentials are needed.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreTerm};
use stack_encrypt::target::{
    AcceptsContext, AeadContext, ContextExtension, DecryptField, DecryptSource, Decryptable,
    Decryption, EncryptTarget, Encryption, NoCallerContext, OptionalContext, RequiredContext,
    ScalarContext,
};
use stack_encrypt::{
    nonempty, Ciphertext, DecryptFrom, EncryptInto, Encrypted, Error, NonEmpty, StackCipherText,
};
use zeroize::Zeroize;
mod common;

// --- The public mixed-record program ---------------------------------------

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

/// Plaintext `id` and `created_at` carried through; `name` and `email`
/// sealed on their own, under `("users", "name")` and `("users", "email")`.
#[derive(EncryptTarget, DecryptSource, Serialize, Deserialize)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

fn alice() -> User {
    User {
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    }
}
fn bob() -> User {
    User {
        id: 43,
        name: "Bob".to_owned(),
        email: "bob@example.com".to_owned(),
        created_at: 1_700_000_100,
    }
}

#[tokio::test]
async fn a_mixed_record_round_trips_through_serde_with_its_passthrough_fields() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let user = alice();

    let encrypted: EncryptedUser = user.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(encrypted.id, user.id);
    assert_eq!(encrypted.created_at, user.created_at);
    // One conversion, one batched key request, one data key per sealed field.
    let generated = sent.lock().unwrap().generate.clone();
    assert_eq!(generated, vec![vec!["users/name", "users/email"]]);

    // Persist the typed output and read it back: plaintext fields as
    // themselves, ciphertext fields as Base64 envelopes.
    let json = serde_json::to_value(&encrypted).unwrap();
    assert_eq!(json["id"], 42);
    assert_eq!(json["created_at"], 1_700_000_000);
    assert!(json["name"].is_string() && json["email"].is_string());
    let loaded: EncryptedUser = serde_json::from_value(json).unwrap();

    let restored = User::decrypt_from(loaded, &cipher).await.unwrap();
    assert_eq!(restored, user);
    let retrieved = sent.lock().unwrap().retrieve.clone();
    assert_eq!(retrieved, vec![vec!["users/name", "users/email"]]);
}

#[tokio::test]
async fn each_sealed_field_is_an_ordinary_ciphertext_under_its_pair() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let encrypted: EncryptedUser = alice().encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<String>(encrypted.name.clone(), ("users", "name"))
            .await
            .unwrap(),
        "Alice"
    );
    assert_eq!(
        String::decrypt_from_with_context(encrypted.email.clone(), &keyset, ("users", "email"))
            .await
            .unwrap(),
        "alice@example.com"
    );
    // The pair is the context: a field moved to the other column is refused.
    assert!(matches!(
        keyset
            .decrypt_with_context::<String>(encrypted.name, ("users", "email"))
            .await,
        Err(Error::Aead)
    ));
}

#[tokio::test]
async fn a_caller_extension_binds_every_sealed_field_to_the_row() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let user = alice();
    let encrypted: EncryptedUser = user
        .clone()
        .encrypt_into_with_context(&keyset, 42u64)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        vec!["(users/name)/42u64", "(users/email)/42u64"]
    );
    // The same extension opens it; another row's id, or none, does not.
    assert!(matches!(
        User::decrypt_from(
            EncryptedUser {
                id: encrypted.id,
                name: encrypted.name.clone(),
                email: encrypted.email.clone(),
                created_at: encrypted.created_at
            },
            &keyset
        )
        .await,
        Err(Error::Aead)
    ));
    assert!(matches!(
        User::decrypt_from_with_context(
            EncryptedUser {
                id: encrypted.id,
                name: encrypted.name.clone(),
                email: encrypted.email.clone(),
                created_at: encrypted.created_at
            },
            &keyset,
            43u64
        )
        .await,
        Err(Error::Aead)
    ));
    assert_eq!(
        User::decrypt_from_with_context(encrypted, &keyset, 42u64)
            .await
            .unwrap(),
        user
    );
}

// --- Ownership: sealed fields wiped, passthrough fields moved -------------

/// A passthrough field type whose `Clone` fails the test: the borrowed
/// form of the record would copy it, and the owned conversion must move it
/// into the output and back instead.
#[derive(Debug, PartialEq, Zeroize)]
struct Handle(u64);
impl Clone for Handle {
    fn clone(&self) -> Self {
        panic!("a passthrough field is moved by the owned conversion, never cloned")
    }
}

/// A sealed field type that records being wiped and refuses to be dropped
/// otherwise.
struct Secret {
    value: String,
    wiped: Arc<AtomicBool>,
}
impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        assert!(self.value.is_empty(), "sealed plaintext dropped unwiped");
    }
}
struct SecretCiphertext(Ciphertext);
impl EncryptTarget<Secret> for SecretCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Secret, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext::<String, K>()
            .project(|secret: &Secret| &secret.value)
            .map(Self)
    }
}
impl DecryptSource<Secret> for SecretCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Secret, K> {
        self.0.decryption(context).map(|value: String| Secret {
            value,
            wiped: Arc::default(),
        })
    }
}
// As a field of a record, a hand-written target says it holds recoverable
// ciphertext and how it opens under the context the record hands it, as a
// hand-written structural target does.
impl Decryptable for SecretCiphertext {
    const DECRYPTABLE: bool = true;
}
impl<Ctx: Into<OptionalContext<ScalarContext>>> DecryptField<Secret, Ctx> for SecretCiphertext {
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Secret, K>> {
        Some(self.decryption(context.into()))
    }
}

#[derive(Zeroize)]
struct Tracked {
    handle: Handle,
    secret: Secret,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tracked, context = "tracked")]
struct EncryptedTracked {
    #[stash(passthrough)]
    handle: Handle,
    secret: SecretCiphertext,
}

#[tokio::test]
async fn the_owned_record_wipes_sealed_fields_and_moves_passthrough_fields() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let wiped = Arc::new(AtomicBool::new(false));
    let tracked = Tracked {
        handle: Handle(7),
        secret: Secret {
            value: "secret".to_owned(),
            wiped: wiped.clone(),
        },
    };
    let pending = tracked.encrypt_into::<EncryptedTracked, _>(&keyset);
    assert!(
        wiped.load(Ordering::SeqCst),
        "the sealed field is wiped before any await"
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    let encrypted = pending.await.unwrap();
    assert_eq!(
        encrypted.handle,
        Handle(7),
        "the passthrough field is moved"
    );
    let opened = Tracked::decrypt_from(encrypted, &keyset).await.unwrap();
    assert_eq!(opened.handle, Handle(7));
    assert_eq!(opened.secret.value, "secret");
    // The caller owns the recovered plaintext; wipe it to satisfy `Secret::drop`.
    let mut opened = opened;
    opened.secret.zeroize();
}

#[tokio::test]
async fn the_owned_record_wipes_sealed_fields_when_the_context_is_refused() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let wiped = Arc::new(AtomicBool::new(false));
    let tracked = Tracked {
        handle: Handle(7),
        secret: Secret {
            value: "secret".to_owned(),
            wiped: wiped.clone(),
        },
    };
    let pending = tracked.encrypt_into_with_context::<EncryptedTracked, _>(
        &keyset,
        NonEmpty::new("x".repeat(65536)).unwrap(),
    );
    assert!(wiped.load(Ordering::SeqCst));
    assert!(pending.await.is_err());
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

// --- The public searchable-record program, as one batch --------------------

/// An application-defined scalar target: the ciphertext plus an equality
/// term, under the one context the record (or the caller) supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct SearchableUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: SearchableEmail,
    #[stash(passthrough)]
    created_at: i64,
}

#[tokio::test]
async fn a_searchable_column_is_one_batch_and_its_terms_match_a_query_term() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let users = vec![alice(), bob()];

    // One collection conversion batches key generation across both users:
    // two name keys and two email keys in one logical call.
    let encrypted: Vec<SearchableUser> = users.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(encrypted.len(), 2);

    // Later: a query under the same keyset, field context and operation,
    // from another cipher, as a query path in another process derives it.
    let reader = common::stack_cipher().await;
    let query: EqualityTerm = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&reader.default_keyset(), nonempty!("users").with("email"))
        .await
        .unwrap();
    // An in-memory scan over the stored rows stands in for the index.
    let matches: Vec<SearchableUser> = encrypted
        .into_iter()
        .filter(|row| row.email.equality == query)
        .collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, 42);

    // The matched rows open in one batch.
    let restored = Vec::<User>::decrypt_from(matches, &cipher).await.unwrap();
    assert_eq!(restored, &users[..1]);
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_searchable_email_standalone_requires_its_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let sealed: SearchableEmail = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    // The record's indexes are its terms'.
    assert_eq!(
        <SearchableEmail as EncryptTarget<String>>::indexes(),
        vec![stack_encrypt::IndexSpec::Equality]
    );
    assert_eq!(
        String::decrypt_from_with_context(sealed, &keyset, nonempty!("users/email"))
            .await
            .unwrap(),
        "alice@example.com"
    );
}

// --- Nested records, renamed sources, pinned identities --------------------

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct Address {
    street: String,
    city: String,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Address, context = "addresses")]
struct EncryptedAddress {
    street: Ciphertext,
    city: Ciphertext,
}

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct Account {
    account_id: u64,
    holder: String,
    address: Address,
    opened: i64,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, context = "accounts")]
struct EncryptedAccount {
    /// A passthrough under another name.
    #[stash(passthrough, from = account_id)]
    id: u64,
    /// A sealed field under another name, keyed under the plaintext field.
    #[stash(from = holder)]
    owner: Ciphertext,
    /// A sealed field keyed under a pinned segment.
    #[stash(from = opened, identity = "opened_at")]
    opened: Ciphertext,
    /// A nested record: its fields sit under their own pairs, extended by
    /// this one.
    address: EncryptedAddress,
}

#[tokio::test]
async fn nested_renamed_and_pinned_fields_compose_their_contexts() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let account = Account {
        account_id: 9,
        holder: "Carol".to_owned(),
        address: Address {
            street: "1 Main St".to_owned(),
            city: "Springfield".to_owned(),
        },
        opened: 1_600_000_000,
    };
    let encrypted: EncryptedAccount = account.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(encrypted.id, 9);
    assert_eq!(
        sent.lock().unwrap().generated(),
        vec![
            "accounts/holder",
            "accounts/opened_at",
            "(addresses/street)/(accounts/address)",
            "(addresses/city)/(accounts/address)",
        ]
    );
    let restored = Account::decrypt_from(encrypted, &keyset).await.unwrap();
    assert_eq!(restored, account);
}

// --- A record that stores its context -------------------------------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct TextEq {
    #[stash(context_field)]
    identifier: &'static str,
    c: Ciphertext,
    hm: EqualityTerm,
}

#[tokio::test]
async fn a_stored_context_opens_as_stored_and_checks_an_expectation() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "alice@example.com".to_owned();
    let encrypted: TextEq = value
        .clone()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(encrypted.identifier, "users/email");
    let generator = common::stack_cipher().await;
    let hm: EqualityTerm = value
        .clone()
        .encrypt_into_with_context(&generator.default_keyset(), nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(encrypted.hm, hm);

    // Omitted: opens under the stored identifier.
    let again = TextEq {
        identifier: encrypted.identifier,
        c: encrypted.c.clone(),
        hm: encrypted.hm.clone(),
    };
    assert_eq!(String::decrypt_from(again, &keyset).await.unwrap(), value);
    // Supplied: the stored identifier must equal it, before any key I/O.
    let moved = TextEq {
        identifier: "users/name",
        c: encrypted.c.clone(),
        hm: encrypted.hm.clone(),
    };
    let before = retrieves.load(Ordering::SeqCst);
    assert!(matches!(
        String::decrypt_from_with_context(moved, &keyset, nonempty!("users/email")).await,
        Err(Error::ContextMismatch { .. })
    ));
    assert_eq!(retrieves.load(Ordering::SeqCst), before);
    assert_eq!(
        String::decrypt_from_with_context(encrypted, &keyset, nonempty!("users/email"))
            .await
            .unwrap(),
        value
    );
}

// --- Plaintext records over the structural leaves and a fixed context -----

/// The hand-written composite in `target.rs`, as an owned record: its
/// fields are the structural leaves, which take the same required context.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

/// A record made only of ciphertexts accepts an AEAD-only context; a term
/// beside them would be refused at its field (`tests/ui`).
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedName {
    #[stash(decrypt)]
    c: StackCipherText,
    #[allow(dead_code)]
    shadow: Ciphertext,
}

/// The ciphertext with its terms, as one structural leaf of an owned record.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Indexed {
    email: Encrypted<(EqualityTerm, MatchTerms)>,
}

/// Generic over the plaintext: whatever every field accepts.
#[derive(EncryptTarget, DecryptSource)]
struct SearchableText {
    c: Ciphertext,
    hm: EqualityTerm,
    m: MatchTerms,
}

#[tokio::test]
async fn plaintext_records_compose_structural_and_opaque_leaves() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = common::stack_cipher().await;
    let generator = generator.default_keyset();

    let age: EncryptedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .unwrap();
    let hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(age.hm, hm);
    assert_eq!(
        <EncryptedAge as EncryptTarget<u32>>::indexes(),
        vec![
            stack_encrypt::IndexSpec::Equality,
            stack_encrypt::IndexSpec::Ore
        ]
    );
    assert_eq!(
        u32::decrypt_from_with_context(age, &keyset, nonempty!("users/age"))
            .await
            .unwrap(),
        42
    );

    let name: SealedName = "Dana"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    assert!(matches!(
        String::decrypt_from_with_context(name, &keyset, nonempty!("users/name")).await,
        Ok(opened) if opened == "Dana"
    ));

    let indexed: Indexed = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(
        <Indexed as EncryptTarget<String>>::indexes().len(),
        2,
        "equality and match"
    );
    assert_eq!(
        String::decrypt_from_with_context(indexed, &keyset, nonempty!("users/email"))
            .await
            .unwrap(),
        "alice@example.com"
    );

    let text: SearchableText = "alice"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    let m: MatchTerms = "alice"
        .to_owned()
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(text.m, m);
    assert_eq!(
        String::decrypt_from_with_context(text, &keyset, nonempty!("users/name"))
            .await
            .unwrap(),
        "alice"
    );
}

// --- A field whose target declares its whole context ----------------------

/// A target that supplies every context itself is a field of a `plaintext`
/// record only through a record that likewise takes none; here it is used
/// standalone and in a column.
struct FixedInteger(Ciphertext);
impl EncryptTarget<i32> for FixedInteger {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .under(nonempty!("users/fixed-age"))
            .accepting()
    }
}
impl DecryptSource<i32> for FixedInteger {
    type ContextInput = NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        self.0
            .decryption(OptionalContext::<ScalarContext>::supplied(
                "users/fixed-age".into(),
            ))
    }
}

#[tokio::test]
async fn an_owned_record_is_a_field_of_a_structural_record_and_a_plan() {
    use stack_encrypt::plan::pick;
    use stack_encrypt::target::legacy::EncryptInto as _;
    use stack_encrypt::{EncryptFrom, Plan};

    #[derive(Clone)]
    struct Profile {
        user: User,
        age: u32,
    }
    /// A structural record holding an owned record as a field: the bridge
    /// makes the owned record an `EncryptFrom` with a `DeclaredContext`.
    #[derive(EncryptFrom)]
    #[stash(struct = Profile, context = "profiles")]
    struct EncryptedProfile {
        user: EncryptedUser,
        #[allow(dead_code)]
        age: EncryptedAge,
    }

    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let profile = Profile {
        user: alice(),
        age: 34,
    };
    let encrypted: EncryptedProfile = profile.encrypt_into(&keyset).await.unwrap();
    assert_eq!(encrypted.user.id, 42);
    assert_eq!(
        sent.lock().unwrap().generated(),
        vec![
            "(users/name)/(profiles/user)",
            "(users/email)/(profiles/user)",
            "profiles/age"
        ]
    );

    // And as a typed field of a plan, through the same bridge.
    let plan = Plan::context("profiles")
        .fields::<Profile, _>()
        .encrypt_into::<EncryptedUser, _>(pick("user", |p: &Profile| &p.user))
        .target::<Ciphertext, _>(pick("age", |p: &Profile| &p.age))
        .build()
        .unwrap();
    let profile = Profile {
        user: bob(),
        age: 51,
    };
    let mut values = cipher.encrypt(&profile).using(&plan).await.unwrap();
    let user: EncryptedUser = values.take("user").unwrap();
    assert_eq!(user.id, 43);
    let age: Ciphertext = values.take("age").unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<u32>(age, ("profiles", "age"))
            .await
            .unwrap(),
        51
    );
    let _ = (
        FixedInteger::encryption::<common::CountingSource>,
        RequiredContext::<u64>::into_inner,
    );
    let _: ContextExtension<u64> =
        <ContextExtension<u64> as stack_encrypt::target::AllowsNoContext>::omitted();
}
