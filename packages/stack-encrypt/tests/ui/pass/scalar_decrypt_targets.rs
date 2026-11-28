//! The targets that one `Ciphertext` decrypts into. Each must compile:
//!
//! - every scalar
//! - a `Protected` of a scalar, and a nullable scalar
//! - a JSON document
//! - the date, timestamp, decimal, and UUID values
//! - a derived newtype of a scalar, with no marker impl written for it
//! - an opaque blob, and a frame
//!
//! `tests/ui/scalar_decrypt_into_a_container.rs` pins the targets that must
//! not compile.
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::value::{Date, Decimal, Timestamp, Uuid};
use stack_encrypt::{
    Ciphertext, Decrypt, DecryptFrom, KeysetCipher, OpaqueBlob, OpaqueDecode, Protected,
    StackCipher,
};
use stack_kms::FakeDataKeySource;

/// A newtype that derives `Decrypt` over a scalar decrypts from one
/// ciphertext with no extra code.
#[derive(Decrypt, zeroize::Zeroize)]
struct Email(String);

/// The same is true for a newtype of an integer, of another newtype, and of
/// a nullable scalar.
#[derive(Decrypt, zeroize::Zeroize)]
struct UserId(u64);
#[derive(Decrypt, zeroize::Zeroize)]
struct PrimaryEmail(Email);
#[derive(Decrypt, zeroize::Zeroize)]
struct Nickname(Option<String>);

/// A whole value stored as one blob decrypts through `OpaqueBlob`.
/// `OpaqueBlob` has its own impl of `OpaqueDecode`.
#[derive(Default, serde::Deserialize, zeroize::Zeroize)]
struct Profile {
    name: String,
}

fn opens<P: OpaqueDecode>() {}

fn targets() {
    opens::<bool>();
    opens::<i8>();
    opens::<i16>();
    opens::<i32>();
    opens::<i64>();
    opens::<i128>();
    opens::<u16>();
    opens::<u32>();
    opens::<u64>();
    opens::<u128>();
    opens::<f32>();
    opens::<f64>();
    opens::<String>();
    opens::<Vec<u8>>();
    opens::<[u8; 16]>();
    opens::<JsonPlaintext>();
    opens::<Date>();
    opens::<Timestamp>();
    opens::<Decimal>();
    opens::<Uuid>();
    opens::<Protected<String>>();
    opens::<Protected<Vec<u8>>>();
    opens::<Protected<i64>>();
    opens::<Option<i64>>();
    opens::<Option<String>>();
    opens::<Protected<Option<i64>>>();
    opens::<Option<Protected<String>>>();
    opens::<OwnedFrame>();
    opens::<Email>();
    opens::<UserId>();
    opens::<PrimaryEmail>();
    opens::<Nickname>();
    opens::<Option<Email>>();
    opens::<OpaqueBlob<Profile>>();
}

async fn calls(
    cipher: &StackCipher<FakeDataKeySource>,
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
    ciphertext: Ciphertext,
) -> Result<(), stack_encrypt::Error> {
    let _: i64 = keyset.decrypt(ciphertext.clone()).await?;
    let _: Protected<String> = keyset
        .decrypt_with_context(ciphertext.clone(), ("users", "email"))
        .await?;
    let _ = keyset.decrypt::<Option<i64>>(ciphertext.clone()).await?;
    let _ = Vec::<u8>::decrypt_from(ciphertext.clone(), keyset).await?;
    let _ = OwnedFrame::decrypt_from(ciphertext.clone(), cipher).await?;
    let _ = Email::decrypt_from(ciphertext.clone(), cipher).await?;
    let _: UserId = keyset.decrypt(ciphertext.clone()).await?;
    // A column of ciphertexts is a `Vec<Ciphertext>`, with one scalar in
    // each ciphertext.
    let _ = Vec::<String>::decrypt_from(vec![ciphertext], keyset).await?;
    Ok(())
}

fn main() {
    let _ = targets;
    let _ = calls;
}
