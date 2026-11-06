//! The plaintext of an owned record must implement `Zeroize`. The conversion
//! is responsible for wiping what it seals, and this bound declares that
//! responsibility.
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
