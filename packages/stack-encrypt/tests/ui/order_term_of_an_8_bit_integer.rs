//! A `u8` and an `i8` have no order term, as a `bool` has none: with 256
//! values, an order term would rank every row among 256, which a few known
//! rows resolve to the values. So neither is `sem::Orderable` or
//! `op::Ordered`: an `OreTerm<u8>`, a plan with `Ore` on an `i8` and an
//! ordering query over a `u8` do not compile. Each keeps its equality term.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::{OpeTerm, OreTerm};
use stack_encrypt::{op, Ore, Plan, StackCipher};

fn terms(ore: OreTerm<u8>, ope: OpeTerm<i8>) {
    let _ = (ore, ope);
}

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let rank_plan = Plan::context("users/rank").with::<i8, _>(Ore).build().unwrap();
    let _ = cipher.query(op::Lt, &7u8).on(&rank_plan);
}

fn main() {}
