use stack_encrypt::{EncryptFrom, StackCipherText, StackCipher, nonempty};
use stack_kms::FakeDataKeySource;
#[derive(Clone, serde::Serialize)]
struct SerdeOnly { value: String }
#[derive(EncryptFrom)]
struct Target { c: StackCipherText }
fn wrong(cipher:&StackCipher<FakeDataKeySource>) {
    let keyset=cipher.default_keyset();
    let _=keyset.encrypt_as::<_,Target>(&SerdeOnly {value:"x".into()},nonempty!("column").into());
}
fn main() {}
