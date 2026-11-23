//! `between` takes two bounds, and the other orderings one value: a query
//! given the wrong shape does not compile.
use stack_encrypt::sem::OreTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    age: u32,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    age: Encrypted<OreTerm<u32>>,
}

fn main() {
    let _ = EncryptedUser::AGE.between(18u32, 65);
    let _ = EncryptedUser::AGE.lt(40u32);
    let _ = EncryptedUser::AGE.between(40u32);
    let _ = EncryptedUser::AGE.lt((18u32, 65u32));
}
