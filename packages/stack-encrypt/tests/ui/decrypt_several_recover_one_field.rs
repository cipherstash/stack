use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    email: String,
}

#[derive(DecryptInto)]
#[stash(struct = User, context = "users")]
struct Rec {
    email: StackCipherText,
    #[stash(from = email, context = "users/email/copy")]
    email_copy: StackCipherText,
}

fn main() {}
