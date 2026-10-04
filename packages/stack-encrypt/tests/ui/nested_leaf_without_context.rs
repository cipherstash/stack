//! A `nested` field is handed the caller's context as it is — `()` in the
//! record's `()` impl. A leaf accepts only a `NonEmpty<_>`, and says so at
//! the field: `nested` is for a field whose type carries its own contexts;
//! a leaf takes the inferred one, or a `context = ".."`.
use stack_encrypt::{DecryptInto, EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(nested)]
    email: StackCipherText,
}

fn main() {}
