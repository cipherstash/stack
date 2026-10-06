//! Match is defined over text, so a match index on an integer does not
//! compile.
use stack_encrypt::target::{indexed, Borrowed, Match};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

fn main() {
    let _ = indexed::<u32, FakeKeysetRegistry, Borrowed, _>(Match::default());
}
