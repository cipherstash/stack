//! A plaintext is sealed through Vitamin C's `Encrypt`. A type that only
//! implements `Serialize` is not a plaintext: there is no Serde fallback.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{nonempty, EncryptInto, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

#[derive(Clone, serde::Serialize, zeroize::Zeroize)]
struct SerdeOnly {
    value: String,
}

#[derive(EncryptTarget)]
struct Target {
    c: StackCipherText,
}

fn wrong(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let plaintext = SerdeOnly { value: "x".into() };
    let _ = plaintext.encrypt_into_with_context::<Target, _>(&keyset, nonempty!("column"));
}

fn main() {}
