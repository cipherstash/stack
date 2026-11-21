//! A field of several indexes answers each operator through the one index
//! that answers it. An operator none of them answers has no method, and
//! neither does one that two of them answer: which index a query used
//! would decide what it reveals.
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreTerm};
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    email: String,
    age: u32,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Encrypted<(EqualityTerm, MatchTerms)>,
    age: Encrypted<(OreTerm<u32>, OpeTerm<u32>)>,
}

fn main() {
    let _ = EncryptedUser::EMAIL.eq("ada@example.com");
    let _ = EncryptedUser::EMAIL.matches("ada");
    let _ = EncryptedUser::EMAIL.gt("ada@example.com");
    let _ = EncryptedUser::AGE.lt(36u32);
}
