//! A declaration describes the encryption, and the library runs it. The
//! trait has no method that is handed the plaintext together with a cipher,
//! so a target cannot add one.
use stack_encrypt::target::{EncryptTarget, NoCallerContext};
use stack_encrypt::{KeysetCipher, Pending};

struct Target;

impl EncryptTarget<u32> for Target {
    type ContextInput = NoCallerContext;
    fn encrypt_from<'a, K>(
        _: &u32,
        cipher: &'a KeysetCipher<'_, K>,
        _: NoCallerContext,
    ) -> Pending<'a, Self, K> {
        Pending::failed(cipher, stack_encrypt::Error::Aead)
    }
}

fn main() {}
