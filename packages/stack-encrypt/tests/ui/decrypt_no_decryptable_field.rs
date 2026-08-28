use stack_encrypt::sem::{EqualityTerm, OreTerm};
use stack_encrypt::DecryptInto;

#[derive(DecryptInto)]
#[stash(plaintext = u32)]
struct Rec {
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

fn main() {}
