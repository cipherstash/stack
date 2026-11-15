//! An exact query term has nothing to verify: the server's answer is the
//! answer, so `verify` on the term of an equality query does not compile.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::Probabilistic;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{Encrypted, StackCipher};
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

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let term = EncryptedUser::EMAIL
        .eq("bob")
        .encrypt(&keyset)
        .await
        .unwrap();
    let _ = term.verify("bob");
}

fn main() {}
