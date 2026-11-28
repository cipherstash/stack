//! A newtype that derives `Encrypt` over one value is one value too. The
//! newtypes here have no `Scalar` impl written by hand.
//!
//! - `keyset.encrypt` encrypts the newtype by itself.
//! - `keyset.encrypt` encrypts it inside a `Protected`, and inside another
//!   such newtype.
//! - A `Vec` of the newtype encrypts one element at a time.
//! - `keyset.encrypt` encrypts a fieldless enum that derives `Encrypt`, with
//!   or without `#[aead(recursive)]`.
//!
//! `tests/ui/scalar_derived_not_one_value.rs` lists the derived types that
//! `keyset.encrypt` refuses.
use stack_encrypt::{Ciphertext, EncryptInto, KeysetCipher, Protected};
use stack_encrypt::Encrypt;
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Encrypt, Zeroize)]
struct Email(String);

#[derive(Encrypt, Zeroize)]
struct Age(i64);

#[derive(Encrypt, Zeroize)]
struct Contact(Email);

#[derive(Encrypt, Zeroize)]
struct Wrapper<T: Zeroize>(T);

#[derive(Encrypt, Zeroize)]
enum Status {
    Active,
    Suspended = 7,
}

#[derive(Encrypt, Zeroize)]
#[aead(recursive)]
enum Level {
    Low,
}

async fn encrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>) {
    let _: Ciphertext = keyset.encrypt(Email("ada@example.com".into())).await.unwrap();
    let _: Ciphertext = keyset.encrypt(Age(37)).await.unwrap();
    let _: Ciphertext = keyset
        .encrypt_with_context(Age(37), ("users", "age"))
        .await
        .unwrap();
    let _: Ciphertext = keyset
        .encrypt(Protected::new(Email("ada@example.com".into())))
        .await
        .unwrap();
    let _: Ciphertext = keyset
        .encrypt(Contact(Email("ada@example.com".into())))
        .await
        .unwrap();
    let _: Ciphertext = keyset.encrypt(Wrapper(37i64)).await.unwrap();
    let _: Ciphertext = keyset.encrypt(Status::Active).await.unwrap();
    let _: Ciphertext = keyset.encrypt(Status::Suspended).await.unwrap();
    let _: Ciphertext = keyset.encrypt(Level::Low).await.unwrap();
    let _: Vec<Ciphertext> = vec![Email("ada@example.com".into()), Email("grace@example.com".into())]
        .encrypt_into(keyset)
        .await
        .unwrap();
}

fn main() {
    let _ = encrypt;
}
