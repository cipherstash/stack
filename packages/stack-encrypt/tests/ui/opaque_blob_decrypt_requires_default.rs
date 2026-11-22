//! Decrypting an `OpaqueBlob<T>` needs `T: Default`: the blob is read in
//! place into a `T::default()` held in a `Zeroizing<T>`, so a refusal part
//! way through the read wipes the fields read before it. `Zeroize` alone is
//! not enough, through `decrypt` or through `decode`.
use serde::Deserialize;
use stack_encrypt::{Ciphertext, KeysetCipher, OpaqueBlob};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Deserialize, Zeroize)]
struct NoDefault {
    name: String,
}

async fn decrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>, ct: Ciphertext) {
    let _refused: OpaqueBlob<NoDefault> = keyset.decrypt(ct).await.unwrap();
}

fn decode(bytes: &[u8]) {
    let _refused = OpaqueBlob::<NoDefault>::decode(bytes);
}

fn main() {}
