use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    email: String,
}

#[derive(DecryptInto)]
#[stash(struct = User, context = "users")]
struct Rec {
    email: StackCipherText,
    #[stash(from = email)]
    email_copy: StackCipherText,
}

fn main() {}
