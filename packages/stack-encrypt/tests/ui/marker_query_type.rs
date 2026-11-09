//! A field marked `#[stash(query = String)]` takes a `String`, or the
//! `&str` it is copied from, and no other type: an integer would match
//! nothing on a text field.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(query = String)]
    email: Encrypted<EqualityTerm>,
}

fn main() {
    let _ = EncryptedUser::EMAIL.eq("ada@example.com");
    let _ = EncryptedUser::EMAIL.eq(String::from("ada@example.com"));
    let _ = EncryptedUser::EMAIL.eq(42u64);
}
