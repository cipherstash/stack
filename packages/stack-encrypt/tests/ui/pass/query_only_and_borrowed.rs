use stack_encrypt::{EncryptFrom, Encrypt, StackCipher, StackCipherText, nonempty};
use stack_encrypt::sem::EqualityTerm;
use stack_kms::FakeDataKeySource;

#[derive(EncryptFrom)]
struct Probe { hm: EqualityTerm }

// No `Decrypt` bound: producing a term requires only that the value
// describes itself, not that it can be read back.
fn query<S: Encrypt + Clone>(cipher:&StackCipher<FakeDataKeySource>, value:&S) {
    let keyset=cipher.default_keyset();
    let _ = keyset.encrypt_as::<_,Probe>(value,nonempty!("column").into());
}
#[derive(EncryptFrom)]
struct Stored { c:StackCipherText }
async fn borrowed(cipher:&StackCipher<FakeDataKeySource>) {
    let keyset=cipher.default_keyset();
    let pending = {
        let text=String::from("borrowed");
        keyset.encrypt_as::<_,Stored>(&text.as_str(),nonempty!("column").into())
    };
    let _ = pending.await.unwrap();
}
fn main() {}
