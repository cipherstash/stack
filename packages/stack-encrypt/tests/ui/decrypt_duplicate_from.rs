//! A plaintext field has one output on the decrypt side too: two fields
//! marked `decrypt` that are derived from the same plaintext field are
//! refused.
use stack_encrypt::target::DecryptSource;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    a: u32,
}

#[derive(DecryptSource)]
#[stash(struct = User, scope = "users")]
struct Rec {
    #[stash(decrypt)]
    a: StackCipherText,
    #[stash(decrypt, from = a)]
    b: StackCipherText,
}

fn main() {}
