//! `OpaqueBlob<T>` needs `T: Zeroize` to encrypt and to decrypt: the owned
//! source is wiped once it is encoded, and the bound is what makes a
//! decrypted value wipeable. `Serialize` alone is not enough.
use serde::{Deserialize, Serialize};
use stack_encrypt::{Ciphertext, KeysetCipher, OpaqueBlob};
use stack_kms::FakeDataKeySource;

#[derive(Serialize, Deserialize)]
struct Unwiped {
    name: String,
}

async fn encrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>, value: Unwiped) {
    let _refused = keyset.encrypt(OpaqueBlob::new(value)).await.unwrap();
}

async fn decrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>, ct: Ciphertext) {
    let _refused: OpaqueBlob<Unwiped> = keyset.decrypt(ct).await.unwrap();
}

fn main() {}
