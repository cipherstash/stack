//! A `struct = ..` record whose plaintext is a generic struct must compile.
//!
//! The derive names the plaintext in a pattern on the encrypt side and in a
//! struct literal on the decrypt side. Both must write the generic arguments
//! with a turbofish (`Pt::<u64> { .. }`). The forms below cover a record with
//! one field and a record with more than one.
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, KeysetCipher};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Pt<T: Zeroize> {
    id: T,
    secret: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Pt<u64>, scope = "points")]
struct EncryptedPt {
    #[stash(passthrough)]
    id: u64,
    secret: Ciphertext,
}

#[derive(Zeroize)]
struct Wrapped<T: Zeroize> {
    secret: T,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Wrapped<String>, scope = "wrapped")]
struct EncryptedWrapped {
    secret: Ciphertext,
}

#[allow(dead_code)]
async fn use_them(keyset: &KeysetCipher<'_, FakeDataKeySource>) {
    let point = Pt {
        id: 7u64,
        secret: "secret".to_owned(),
    };
    let encrypted: EncryptedPt = point.encrypt_into(keyset).await.unwrap();
    let _opened = Pt::<u64>::decrypt_from(encrypted, keyset).await.unwrap();

    let wrapped = Wrapped {
        secret: "secret".to_owned(),
    };
    let encrypted: EncryptedWrapped = wrapped.encrypt_into(keyset).await.unwrap();
    let _opened = Wrapped::<String>::decrypt_from(encrypted, keyset)
        .await
        .unwrap();
}

fn main() {}
