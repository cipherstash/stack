//! A record of one-way terms alone holds no ciphertext, so it cannot derive
//! `DecryptSource`.
use stack_encrypt::sem::{EqualityTerm, OreTerm};
use stack_encrypt::target::DecryptSource;

#[derive(DecryptSource)]
#[stash(plaintext = u32)]
struct Rec {
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

fn main() {}
