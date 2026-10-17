//! The ordering operators are answered over the integer types. Text has no
//! order term this crate produces, so an ordering on a text plan does not
//! compile, even where the plan declares an ORE index.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op;
use stack_encrypt::{Ore, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let name_plan = Plan::context("users/name")
        .with::<String, _>(Ore)
        .build()
        .unwrap();
    let _ = cipher.query(op::Lt, "nguyen").on(&name_plan);
}

fn main() {}
