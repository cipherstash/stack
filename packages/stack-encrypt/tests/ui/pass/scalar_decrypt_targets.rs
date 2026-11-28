//! The targets one `Ciphertext` decrypts into, which must compile: every
//! scalar, a `Protected` of one, a nullable one, a JSON document, the date,
//! timestamp, decimal and UUID values, an opaque blob and a frame.
//! `tests/ui/scalar_decrypt_into_a_container.rs` pins the targets that must
//! not.
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::value::{Date, Decimal, Timestamp, Uuid};
use stack_encrypt::{
    Ciphertext, Decrypt, DecryptFrom, KeysetCipher, OpaqueBlob, OpaqueDecode, Protected,
    ScalarTarget, StackCipher,
};
use stack_kms::FakeDataKeySource;

/// A newtype that derives `Decrypt` over a scalar. Its author adds the
/// marker, because the derive does not.
#[derive(Decrypt, zeroize::Zeroize)]
struct Email(String);
impl ScalarTarget for Email {}

/// A whole value stored as one blob keeps its own way in.
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
    // A column of ciphertexts is a `Vec` of them, one scalar each.
    let _ = Vec::<String>::decrypt_from(vec![ciphertext], keyset).await?;
    Ok(())
}

fn main() {
    let _ = targets;
    let _ = calls;
}
