//! The JSON operators are answered by the JSON index alone, over a
//! `serde_json::Value`: on a plan over text with an equality index, a
//! containment query and a query at a path do not compile, because the plan
//! declares no index that answers them and its plaintext is not a document.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op;
use stack_encrypt::{Equality, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let profile_plan = Plan::context("users/profile")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let _ = cipher.query(op::Contains, "{}").on(&profile_plan);
    let _ = cipher
        .query(op::AtPath(op::Eq), &("$.address.city", "Sydney"))
        .on(&profile_plan);
}

fn main() {}
