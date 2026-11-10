//! A `plaintext = T` record has no context of its own: every output shares
//! the caller's, so it lists no scope or binding.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(EncryptTarget)]
#[stash(plaintext = String, scope(tenant: u64))]
struct Scoped {
    c: StackCipherText,
    hm: EqualityTerm,
}

#[derive(EncryptTarget)]
#[stash(plaintext = String, bind(row: u128))]
struct Bound {
    c: StackCipherText,
    hm: EqualityTerm,
}

fn main() {}
