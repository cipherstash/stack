use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    email: String,
}

#[derive(DecryptInto)]
#[stash(plaintext = User)]
struct Rec {
    #[stash(from = email, context = "users/email")]
    email: StackCipherText,
    #[stash(from = email, context = "users/email/copy")]
    email_copy: StackCipherText,
}

fn main() {}
