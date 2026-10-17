//! A target answers only the operators its type implements `Answers` for:
//! an equality term is not searchable text.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{op, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let email_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<EqualityTerm>()
        .build()
        .unwrap();
    let _ = cipher.query(op::Matches, "bob").on(&email_plan);
}

fn main() {}
