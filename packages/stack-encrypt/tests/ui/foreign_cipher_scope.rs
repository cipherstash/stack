//! `CipherScope` is sealed: a scope names a keyset the cipher loaded from
//! ZeroKMS, so an outside crate cannot invent one that claims an id it does
//! not hold.

use stack_encrypt::target::CipherScope;
use stack_encrypt::StackCipher;
use uuid::Uuid;

struct AnyKeyset<'a, K>(&'a StackCipher<K>, Uuid);

impl<'a, K> CipherScope<'a, K> for AnyKeyset<'a, K> {
    fn cipher(&self) -> &'a StackCipher<K> {
        self.0
    }

    fn keyset(&self) -> Option<Uuid> {
        Some(self.1)
    }
}

fn main() {}
