//! A `from` field is never handed the caller's context: it is derived under
//! its own `context`, or under `()` if it has none. A leaf refuses `()`, and
//! says so at the field — the fix is a `context = ".."` on it.
use stack_encrypt::{DecryptInto, EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = User)]
struct EncryptedUser {
    #[stash(from = email)]
    email: StackCipherText,
}

fn main() {}
