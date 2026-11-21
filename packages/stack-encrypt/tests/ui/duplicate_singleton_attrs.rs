//! Every attribute except `plaintext` is given once. Repeating one is
//! refused at the second.
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::StackCipherText;

struct User {
    expected: u32,
    other: u32,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct DupFrom {
    #[stash(from = expected, from = other)]
    c: StackCipherText,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct DupIdentity {
    #[stash(identity = "email", identity = "name")]
    expected: StackCipherText,
}

#[derive(EncryptTarget)]
struct DupDefault {
    c: StackCipherText,
    #[stash(default, default = 3)]
    v: u8,
}

#[derive(DecryptSource)]
struct DupDecrypt {
    #[stash(decrypt, decrypt)]
    c: StackCipherText,
}

#[derive(EncryptTarget)]
#[stash(crate = "stack_encrypt", crate = "stack_encrypt")]
struct DupCrate {
    c: StackCipherText,
}

fn main() {}
