//! One inapplicable index makes the whole set inapplicable: equality is
//! defined over `u32`, match is not.
use stack_encrypt::target::{indexed, Borrowed, Equality, Match};
use stack_kms::FakeDataKeySource;

fn main() {
    let _ = indexed::<u32, FakeDataKeySource, Borrowed, _>((Equality, Match::default()));
}
