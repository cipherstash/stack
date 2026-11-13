//! A `CipherRef` is built from a reference to a cipher and in no other
//! way. Its fields are private. So an outside crate cannot build one that
//! names a keyset the cipher did not load from ZeroKMS.

use stack_encrypt::{CipherRef, StackCipher};
use uuid::Uuid;

fn any_keyset<K>(cipher: &StackCipher<K>, id: Uuid) -> CipherRef<'_, K> {
    CipherRef {
        cipher,
        keyset: Some(id),
    }
}

fn main() {}
