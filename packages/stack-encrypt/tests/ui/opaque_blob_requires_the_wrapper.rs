//! A struct is not a scalar: `encrypt` refuses it however it serializes.
//! There is no `Serialize` fallback; a whole value is one ciphertext only
//! when the caller names `OpaqueBlob`.
use serde::Serialize;
use stack_encrypt::{KeysetCipher, OpaqueBlob};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Serialize, Zeroize)]
struct Profile {
    name: String,
    age: u32,
}

async fn encrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>, profile: Profile) {
    let _refused = keyset.encrypt(profile).await.unwrap();
}

async fn encrypt_wrapped(keyset: &KeysetCipher<'_, FakeDataKeySource>, profile: Profile) {
    let _sealed = keyset.encrypt(OpaqueBlob::new(profile)).await.unwrap();
}

fn main() {}
