//! The owned record forms that must compile: a `struct = ..` record with
//! passthrough, renamed, pinned and nested fields; `plaintext` records over
//! opaque and structural leaves, generic, and with a stored context; a column
//! of records; and the structural bridge into a legacy record and a plan.
//! `tests/ui/owned_record_*.rs` and `tests/ui/passthrough_misuse.rs` pin the
//! forms that must not.
use stack_encrypt::plan::pick;
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreTerm};
use stack_encrypt::target::{legacy, AeadContext, DecryptSource, EncryptTarget};
use stack_encrypt::{
    nonempty, Ciphertext, DecryptFrom, EncryptFrom, EncryptInto, Encrypted, KeysetCipher, Plan,
    StackCipher, StackCipherText,
};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct Address {
    street: String,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Address, context = "addresses")]
struct EncryptedAddress {
    street: Ciphertext,
}

#[derive(Clone, Zeroize)]
struct User {
    id: u64,
    name: String,
    email: String,
    address: Address,
    created: i64,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(passthrough)]
    id: u64,
    #[stash(from = name, identity = "full_name")]
    full_name: Ciphertext,
    email: SearchableEmail,
    address: EncryptedAddress,
    #[stash(passthrough, from = created)]
    created_at: i64,
    #[stash(default)]
    version: u8,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedName {
    c: StackCipherText,
}

#[derive(EncryptTarget, DecryptSource)]
struct Searchable {
    c: Encrypted<(EqualityTerm, MatchTerms)>,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct TextEq {
    #[stash(context_field)]
    identifier: &'static str,
    c: Ciphertext,
    hm: EqualityTerm,
}

/// The structural bridge: an owned record as a field of a structural one.
#[derive(Clone)]
struct Profile {
    user: User,
    age: u32,
}
#[derive(EncryptFrom)]
#[stash(struct = Profile, context = "profiles")]
struct EncryptedProfile {
    user: EncryptedUser,
    age: EncryptedAge,
}

async fn records(
    cipher: &StackCipher<FakeDataKeySource>,
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
    user: User,
    profile: Profile,
) -> Result<(), stack_encrypt::Error> {
    // A struct record, with and without an extension, and as a column.
    let encrypted: EncryptedUser = user.clone().encrypt_into(keyset).await?;
    let _: User = User::decrypt_from(encrypted, cipher).await?;
    let encrypted: EncryptedUser = user.clone().encrypt_into_with_context(keyset, 7u64).await?;
    let _: User = User::decrypt_from_with_context(encrypted, keyset, 7u64).await?;
    let column: Vec<EncryptedUser> = vec![user.clone()].encrypt_into(keyset).await?;
    let _: Vec<User> = Vec::decrypt_from(column, cipher).await?;

    // Plaintext records require their context.
    let email: SearchableEmail = user
        .email
        .clone()
        .encrypt_into_with_context(keyset, nonempty!("users/email"))
        .await?;
    let _: String = String::decrypt_from_with_context(email, keyset, nonempty!("users/email")).await?;
    let age: EncryptedAge = 34u32.encrypt_into_with_context(keyset, nonempty!("users/age")).await?;
    let _: u32 = u32::decrypt_from_with_context(age, keyset, nonempty!("users/age")).await?;
    let name: SealedName = user
        .name
        .clone()
        .encrypt_into_with_context(keyset, nonempty!("users/name"))
        .await?;
    let _: String = String::decrypt_from_with_context(name, keyset, nonempty!("users/name")).await?;
    let text: Searchable = user
        .name
        .clone()
        .encrypt_into_with_context(keyset, nonempty!("users/name"))
        .await?;
    let _: String = String::decrypt_from_with_context(text, keyset, nonempty!("users/name")).await?;

    // A stored context: omitted opens as stored, supplied also checks it.
    let stored: TextEq = user
        .email
        .clone()
        .encrypt_into_with_context(keyset, nonempty!("users/email"))
        .await?;
    let _: String = String::decrypt_from_with_context(stored, keyset, nonempty!("users/email")).await?;
    let stored: TextEq = user
        .email
        .encrypt_into_with_context(keyset, nonempty!("users/email"))
        .await?;
    let _: String = String::decrypt_from(stored, keyset).await?;

    // The bridge: in a structural record, and as a typed plan field.
    let _: EncryptedProfile = legacy::EncryptInto::encrypt_into(&profile, keyset).await?;
    let plan = Plan::context("profiles")
        .fields::<Profile, _>()
        .encrypt_into::<EncryptedUser, _>(pick("user", |p: &Profile| &p.user))
        .target::<Ciphertext, _>(pick("age", |p: &Profile| &p.age))
        .build()?;
    let _ = cipher.encrypt(&profile).using(&plan).await?;
    Ok(())
}

fn main() {
    let _ = records;
}
