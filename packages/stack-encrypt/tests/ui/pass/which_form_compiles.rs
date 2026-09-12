//! The three record shapes and the call forms each accepts. Every line here
//! must compile; `tests/ui/leaf_without_context.rs` and
//! `tests/ui/bare_context.rs` pin the lines that must not.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, KeysetCipher, NonEmpty, StackCipherText};
use stack_kms::FakeDataKeySource;

/// Encrypting binds to a keyset; decrypting works through the same handle
/// (constrained to that keyset) as well as through the `StackCipher`.
type Cipher<'k> = KeysetCipher<'k, FakeDataKeySource>;

/// A record whose one field pins a literal context: needs nothing from the
/// caller, and takes a context that then *extends* the literal.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Pinned {
    #[stash(context = "legacy/age")]
    c: StackCipherText,
}

async fn pinned(cipher: &Cipher<'_>, tenant_id: u64) -> Result<(), stack_encrypt::Error> {
    // Sealed under "legacy/age".
    let p: Pinned = 42u32.encrypt_into(cipher).await?;
    let _: u32 = p.decrypt_into(cipher, ()).await?;
    // Sealed under ("legacy/age", tenant_id).
    let p: Pinned = 42u32.encrypt_into_with_context(cipher, tenant_id).await?;
    let _: u32 = p.decrypt_into(cipher, NonEmpty::from(tenant_id)).await?;
    Ok(())
}

/// A record whose fields have no context of their own: the caller's is
/// the only one there is, so it must be given.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Foo {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn foo(cipher: &Cipher<'_>, column: String) -> Result<(), stack_encrypt::Error> {
    // A literal, a runtime value, a bare integer.
    let f: Foo = 42u32.encrypt_into_with_context(cipher, nonempty!("users/age")).await?;
    let _: u32 = f.decrypt_into(cipher, nonempty!("users/age")).await?;
    let f: Foo = 42u32
        .encrypt_into_with_context(cipher, NonEmpty::new(column.clone()).expect("non-empty"))
        .await?;
    let _: u32 = f
        .decrypt_into(cipher, NonEmpty::new(column).expect("non-empty"))
        .await?;
    let f: Foo = 42u32.encrypt_into_with_context(cipher, 7u64).await?;
    let _: u32 = f.decrypt_into(cipher, NonEmpty::from(7u64)).await?;
    Ok(())
}

/// A struct encrypted field by field: every field has an inferred context,
/// and the caller's extends all of them.
struct User {
    age: u32,
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    age: Foo,
    email: StackCipherText,
}

async fn user(cipher: &Cipher<'_>, user: User, id: u64) -> Result<(), stack_encrypt::Error> {
    // "users/age", "users/email".
    let r: EncryptedUser = user.encrypt_into(cipher).await?;
    let user = User::decrypt_from(r, cipher).await?;
    // ("users/age", id), ("users/email", id).
    let r: EncryptedUser = user.encrypt_into_with_context(cipher, id).await?;
    let _: EqualityTerm = 42u32
        .encrypt_into_with_context(cipher, nonempty!("users/age").with(id))
        .await?;
    let _ = User::decrypt_from_with_context(r, cipher, id).await?;
    Ok(())
}

fn main() {
    let _ = pinned;
    let _ = foo;
    let _ = user;
}
