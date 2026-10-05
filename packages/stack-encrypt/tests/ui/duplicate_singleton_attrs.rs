use stack_encrypt::{DecryptInto, EncryptFrom, StackCipherText};

struct User {
    expected: u32,
    other: u32,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct DupFrom {
    #[stash(from = expected, from = other)]
    c: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct DupIdentity {
    #[stash(identity = "email", identity = "name")]
    expected: StackCipherText,
}

#[derive(EncryptFrom)]
struct DupDefault {
    c: StackCipherText,
    #[stash(default, default = 3)]
    v: u8,
}

#[derive(DecryptInto)]
struct DupDecrypt {
    #[stash(decrypt, decrypt)]
    c: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(crate = "stack_encrypt", crate = "stack_encrypt")]
struct DupCrate {
    c: StackCipherText,
}

fn main() {}
