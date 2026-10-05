//! `context_type` names what the caller passes to a record whose fields take
//! the caller's context. The three shapes that settle the context themselves
//! refuse it, and like every other singular attribute it is given once.
use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users", context_type = stack_encrypt::target::AeadContext)]
struct ByField {
    name: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(plaintext = String, context_type = stack_encrypt::target::AeadContext)]
struct Stored {
    #[stash(context_field)]
    tenant: String,
    c: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(plaintext = String, context_type = stack_encrypt::target::AeadContext)]
struct Declared {
    #[stash(context = "name")]
    c: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(context_type = stack_encrypt::target::AeadContext, context_type = stack_encrypt::target::AeadContext)]
struct Twice {
    c: StackCipherText,
}

fn main() {}
