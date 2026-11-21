//! A field is derived from the plaintext field of its own name; a name the
//! plaintext does not have is reported by rustc at the field.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "user")]
struct EncryptedUser {
    email: StackCipherText,
    nickname: StackCipherText,
}

fn main() {}
