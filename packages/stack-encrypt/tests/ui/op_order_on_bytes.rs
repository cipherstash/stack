//! The ordering operators are answered over the integer types, the floats and text.
//! Bytes have no order key the ordering operators compare, so an ordering on
//! a bytes plan does not compile, even where the plan declares an ORE index.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op;
use stack_encrypt::{Ore, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let blob_plan = Plan::context("users/blob")
        .with::<Vec<u8>, _>(Ore)
        .build()
        .unwrap();
    let _ = cipher.query(op::Lt, &vec![1u8, 2]).on(&blob_plan);
}

fn main() {}
