use stack_encrypt::target::CallerContext;
use stack_encrypt::{Encryption, StackCipherText};
fn main() {
    // Target authors cannot install a callback that receives plaintext + cipher.
    let _: Encryption<'_, u32, StackCipherText, (), CallerContext> = Encryption {
        build: Box::new(|_, cipher, _| {
            stack_encrypt::Pending::failed(cipher, stack_encrypt::Error::Aead)
        }),
    };
}
