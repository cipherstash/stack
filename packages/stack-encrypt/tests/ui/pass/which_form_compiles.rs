//! The record shapes and the call forms each accepts. Every line here
//! must compile; `tests/ui/leaf_without_context.rs`,
//! `tests/ui/bare_context.rs` and
//! `tests/ui/owned_struct_record_takes_no_context.rs` pin the lines that
//! must not.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget, Scope};
use stack_encrypt::{
    nonempty, DecryptFrom, EncryptInto, KeysetCipher, NonEmpty, StackCipher, StackCipherText,
};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

/// Encrypting binds to a keyset; decrypting works through the same handle
/// (constrained to that keyset) as well as through the `StackCipher`.
type Cipher<'k> = KeysetCipher<'k, FakeDataKeySource>;

/// A record whose fields have no context of their own: the caller's is
/// the only one there is, so it must be given.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct Foo {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn foo(
    keyset: &Cipher<'_>,
    cipher: &StackCipher<FakeDataKeySource>,
    column: String,
) -> Result<(), stack_encrypt::Error> {
    // A literal, a runtime value, a bare integer.
    let f: Foo = 42u32
        .encrypt_into_with_context(keyset, nonempty!("users/age"))
        .await?;
    let _: u32 = u32::decrypt_from_with_context(f, keyset, nonempty!("users/age")).await?;
    let f: Foo = 42u32
        .encrypt_into_with_context(keyset, NonEmpty::new(column.clone()).expect("non-empty"))
        .await?;
    let _: u32 =
        u32::decrypt_from_with_context(f, cipher, NonEmpty::new(column).expect("non-empty"))
            .await?;
    let f: Foo = 42u32.encrypt_into_with_context(keyset, 7u64).await?;
    let _: u32 = u32::decrypt_from_with_context(f, cipher, NonEmpty::from(7u64)).await?;
    Ok(())
}

/// A struct encrypted field by field: every field has a context of its
/// own, so the caller passes none.
#[derive(Zeroize)]
struct User {
    age: u32,
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    age: Foo,
    email: StackCipherText,
}

/// The same struct under a scope the caller supplies: the scope extends
/// every field's context, and the caller passes it on every call.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct TenantUser {
    age: Foo,
    email: StackCipherText,
}

async fn user(keyset: &Cipher<'_>, user: User, id: u64) -> Result<(), stack_encrypt::Error> {
    // ("users", "age"), ("users", "email").
    let r: EncryptedUser = user.encrypt_into(keyset).await?;
    let _: EqualityTerm = 42u32
        .encrypt_into_with_context(keyset, nonempty!("users").with("age"))
        .await?;
    let user = User::decrypt_from(r, keyset).await?;
    // The same two contexts, each extended by the tenant.
    let r: TenantUser = user
        .encrypt_into_with_context(keyset, Scope::new(id))
        .await?;
    let _ = User::decrypt_from_with_context(r, keyset, Scope::new(id)).await?;
    Ok(())
}

fn main() {
    let _ = foo;
    let _ = user;
}
