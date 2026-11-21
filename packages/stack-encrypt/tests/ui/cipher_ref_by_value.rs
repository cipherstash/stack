//! A decrypt runs through a reference to the client, not the client
//! itself. Passing the `StackCipher` by value fails, and the compiler
//! suggests borrowing it.

use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{Ciphertext, DecryptFrom, StackCipher};

fn by_value(ciphertext: Ciphertext, cipher: StackCipher<FakeDataKeySource>) {
    let _ = i32::decrypt_from(ciphertext, cipher);
}

fn main() {}
