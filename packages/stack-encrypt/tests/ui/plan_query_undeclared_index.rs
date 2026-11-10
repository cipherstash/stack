//! A one-value plan selects a query's index by type, so asking it for an
//! index it does not hold does not compile.
use stack_encrypt::op;
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{Ore, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let age_plan = Plan::context("users/age").with::<u32, _>(Ore).build().unwrap();
    let _ = cipher.query(op::Eq, &34u32).on(&age_plan);
}

fn main() {}
