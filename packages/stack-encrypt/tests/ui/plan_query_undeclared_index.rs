//! A one-value plan selects a query's index by type, so asking it for an
//! index it does not hold does not compile.
use stack_encrypt::registry::fake::FakeKeysetRegistry;
use stack_encrypt::{Ore, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeKeysetRegistry>) {
    let age_plan = Plan::context("users/age").with::<u32, _>(Ore).build().unwrap();
    let _ = cipher.query(&34u32).using(&age_plan).equality();
}

fn main() {}
