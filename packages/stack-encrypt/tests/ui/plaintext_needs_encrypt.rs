use stack_encrypt::{EncryptFrom, StackCipherText, StackCipher, nonempty};
use stack_encrypt::registry::fake::FakeKeysetRegistry;
#[derive(Clone, serde::Serialize)]
struct SerdeOnly { value: String }
#[derive(EncryptFrom)]
struct Target { c: StackCipherText }
fn wrong(cipher:&StackCipher<FakeKeysetRegistry>) {
    let keyset=cipher.default_keyset();
    let _=keyset.encrypt_as::<_,Target>(&SerdeOnly {value:"x".into()},nonempty!("column").into());
}
fn main() {}
