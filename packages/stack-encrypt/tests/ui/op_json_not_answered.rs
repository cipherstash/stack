//! The JSON operators are declared and answered by no index: this crate has
//! no JSON index, so a containment query and a query at a path do not
//! compile on any plan.
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
