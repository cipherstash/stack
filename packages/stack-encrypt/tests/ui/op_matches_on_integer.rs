//! `Matches` is text search: a field of integers has no index that answers
//! it, so the query does not compile.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{op, Equality, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let age_plan = Plan::context("users/age").with::<u32, _>(Equality).build().unwrap();
    let _ = cipher.query(op::Matches, &34u32).on(&age_plan);
}

fn main() {}
