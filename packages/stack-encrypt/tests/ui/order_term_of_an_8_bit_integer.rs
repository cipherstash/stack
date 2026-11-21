//! A `u8` and an `i8` have no order term, as a `bool` has none: with 256
//! values, an order term would rank every row among 256, which a few known
//! rows resolve to the values. So neither is `sem::Orderable`: an
//! `OreTerm<u8>`, an `OpeTerm<i8>` and an `Ore` index on an `i8` do not
//! compile. A field with no order term has no ordering query. Each keeps
//! its equality term.
use stack_encrypt::sem::{OpeTerm, OreTerm};
use stack_encrypt::target::{indexed, Borrowed, Ore};
use stack_kms::FakeDataKeySource;

fn terms(ore: OreTerm<u8>, ope: OpeTerm<i8>) {
    let _ = (ore, ope);
}

fn main() {
    let _ = indexed::<i8, FakeDataKeySource, Borrowed, _>(Ore);
}
