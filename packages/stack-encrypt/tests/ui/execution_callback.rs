use stack_encrypt::{Encryption, StackCipherText};
fn main() {
    // Target authors cannot install a callback that receives plaintext + cipher.
    let _: Encryption<'_, u32, StackCipherText, ()> = Encryption {
        build: Box::new(|_, cipher| stack_encrypt::Pending::failed(cipher, stack_encrypt::Error::Aead)),
    };
}
