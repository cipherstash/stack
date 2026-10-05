//! One inapplicable index makes the whole set inapplicable: equality is
//! defined over `u32`, match is not.
use stack_encrypt::target::{indexed, Borrowed, Equality, Match};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

fn main() {
    let _ = indexed::<u32, FakeKeysetRegistry, Borrowed, _>((Equality, Match::default()));
}
