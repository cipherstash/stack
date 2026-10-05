use stack_encrypt::{EncryptFrom, StackCipher, StackCipherText, nonempty};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::registry::fake::FakeKeysetRegistry;

#[derive(EncryptFrom)]
struct Probe { hm: EqualityTerm }

// No Encrypt bound: producing a term requires only the PRF capability.
fn query<S: vitaminc_prf::PrfValue + Clone>(cipher:&StackCipher<FakeKeysetRegistry>, value:&S) {
    let keyset=cipher.default_keyset();
    let _ = keyset.encrypt_as::<_,Probe>(value,nonempty!("column").into());
}
#[derive(EncryptFrom)]
struct Stored { c:StackCipherText }
async fn borrowed(cipher:&StackCipher<FakeKeysetRegistry>) {
    let keyset=cipher.default_keyset();
    let pending = {
        let text=String::from("borrowed");
        keyset.encrypt_as::<_,Stored>(&text.as_str(),nonempty!("column").into())
    };
    let _ = pending.await.unwrap();
}
fn main() {}
