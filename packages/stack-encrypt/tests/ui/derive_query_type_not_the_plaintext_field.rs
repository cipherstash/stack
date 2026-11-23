//! `#[stash(query = T)]` names the plaintext field's type, or the type
//! inside its `Option`. The derive checks it against the plaintext struct.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    email: String,
    nick: Option<String>,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(query = u64)]
    email: Encrypted<EqualityTerm>,
    #[stash(query = String)]
    nick: Option<Encrypted<EqualityTerm>>,
}

fn main() {}
