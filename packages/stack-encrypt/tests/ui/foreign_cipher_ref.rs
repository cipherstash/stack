//! A `CipherRef` is built from a reference to a cipher and in no other
//! way. Its fields are private. So an outside crate cannot build one that
//! names a keyset the cipher did not load from ZeroKMS.

use stack_encrypt::{CipherRef, StackCipher};

fn any_keyset<K>(cipher: &StackCipher<K>) -> CipherRef<'_, K> {
    CipherRef {
        cipher,
        // Whatever the field is given: it cannot be named from here.
        keyset: unimplemented!(),
    }
}

fn main() {}
