use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    email: String,
}

#[derive(DecryptInto)]
#[stash(plaintext = User)]
struct Rec {
    #[stash(from = email, context = "users/email")]
    email: StackCipherText,
    hm: EqualityTerm,
}

fn main() {}
