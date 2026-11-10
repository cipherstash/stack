//! `Between` takes a pair of bounds, and the other orderings one value: a
//! query given the wrong shape does not compile.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op;
use stack_encrypt::{Ore, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let age_plan = Plan::context("users/age")
        .with::<u32, _>(Ore)
        .build()
        .unwrap();
    let _ = cipher.query(op::Between, &40u32).on(&age_plan);
    let _ = cipher.query(op::Lt, &(18u32, 65)).on(&age_plan);
}

fn main() {}
