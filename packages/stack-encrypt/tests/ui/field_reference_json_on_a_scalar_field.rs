//! The JSON queries belong to a field whose type stores a JSON document.
//! A field of `Encrypted<EqualityTerm>` has `eq` and no `contains`, `at`,
//! `elements`, `predicate` or `children`.
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
    email: Encrypted<EqualityTerm>,
}

fn main() {
    let _ = EncryptedUser::EMAIL.contains(serde_json::json!({"a": 1}));
    let _ = EncryptedUser::EMAIL.at();
    let _ = EncryptedUser::EMAIL.at_text_path("$.a");
}
