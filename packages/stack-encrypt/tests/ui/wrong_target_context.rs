//! A record that stores its context takes a `NonEmpty<T>` of the stored
//! field's type, and no other.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{nonempty, EncryptInto, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

#[derive(EncryptTarget)]
#[stash(plaintext = String)]
struct Target {
    #[stash(context_field)]
    identifier: u32,
    c: StackCipherText,
}

fn wrong(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let _ = "value"
        .to_owned()
        .encrypt_into_with_context::<Target, _>(&keyset, nonempty!("wrong type"));
}

fn main() {}
