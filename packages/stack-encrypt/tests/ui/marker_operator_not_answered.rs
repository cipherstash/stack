//! A field marker has one method per operator the field's indexes answer.
//! `Encrypted<EqualityTerm>` answers `eq` alone, so its marker has no `gt`;
//! `Encrypted<OreTerm<u32>>` answers the orderings and no `matches`.
use stack_encrypt::sem::{EqualityTerm, OreTerm};
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
    email: Encrypted<EqualityTerm>,
    age: Encrypted<OreTerm<u32>>,
}

fn main() {
    let _ = EncryptedUser::EMAIL.eq("ada@example.com");
    let _ = EncryptedUser::EMAIL.gt("ada@example.com");
    let _ = EncryptedUser::AGE.between(&18u32, &65);
    let _ = EncryptedUser::AGE.matches("36");
}
