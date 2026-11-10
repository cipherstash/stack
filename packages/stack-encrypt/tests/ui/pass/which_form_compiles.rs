//! The two record shapes and the call forms each accepts. Every line here
//! must compile; `tests/ui/leaf_without_context.rs` and
//! `tests/ui/bare_context.rs` pin the lines that must not.
use stack_encrypt::sem::EqualityTerm;

use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, KeysetCipher, NonEmpty, StackCipherText};
use stack_kms::FakeDataKeySource;

/// Encrypting binds to a keyset; decrypting works through the same handle
/// (constrained to that keyset) as well as through the `StackCipher`.
type Cipher<'k> = KeysetCipher<'k, FakeDataKeySource>;

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
    let f: Foo = cipher.encrypt_as(&42u32, nonempty!("users/age").into()).await?;
    let _: u32 = cipher.decrypt_as(f, nonempty!("users/age").into()).await?;
    let f: Foo = cipher.encrypt_as(&42u32, NonEmpty::new(column.clone()).expect("non-empty").into())
        .await?;
    let _: u32 = cipher.decrypt_as(f, NonEmpty::new(column).expect("non-empty").into())
        .await?;
    let f: Foo = cipher.encrypt_as(&42u32, 7u64.into()).await?;
    let _: u32 = cipher.decrypt_as(f, NonEmpty::from(7u64).into()).await?;
    Ok(())
}

/// A struct encrypted field by field: every field has an inferred context,
/// and the caller's extends all of them.
struct User {
    age: u32,
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    age: Foo,
    email: StackCipherText,
}

async fn user(cipher: &Cipher<'_>, user: User, id: u64) -> Result<(), stack_encrypt::Error> {
    // "users/age", "users/email".
    let r: EncryptedUser = cipher.encrypt_as(&user, Default::default()).await?;
    let user = cipher.decrypt_as::<User, _>(r, Default::default()).await?;
    // ("users/age", id), ("users/email", id).
    let r: EncryptedUser = cipher.encrypt_as(&user, id.into()).await?;
    let _: EqualityTerm = cipher.encrypt_as(&42u32, nonempty!("users/age").with(id).into())
        .await?;
    let _ = cipher.decrypt_as::<User, _>(r, id.into()).await?;
    Ok(())
}

fn main() {
    let _ = foo;
    let _ = user;
}
