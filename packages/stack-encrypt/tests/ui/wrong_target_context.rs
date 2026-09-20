use stack_encrypt::{EncryptFrom, StackCipherText, StackCipher, nonempty};
use stack_kms::FakeDataKeySource;
#[derive(EncryptFrom)]
#[stash(plaintext = String)]
struct Target {
    #[stash(context_field)]
    identifier: u32,
    c: StackCipherText,
}
fn wrong(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let _ = keyset.encrypt_as::<_,Target>(&"value".to_owned(), nonempty!("wrong type"));
}
fn main() {}
