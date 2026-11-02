//! The plaintext of an owned record is a `Zeroize` type: the conversion
//! takes responsibility for wiping what it seals, and the bound is where
//! that responsibility is declared.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Ciphertext;

struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: Ciphertext,
}

fn main() {}
