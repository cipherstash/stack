use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    a: u32,
}

#[derive(DecryptInto)]
#[stash(struct = User, scope = "users")]
struct Rec {
    #[stash(decrypt)]
    a: StackCipherText,
    #[stash(decrypt, from = a)]
    b: StackCipherText,
}

fn main() {}
