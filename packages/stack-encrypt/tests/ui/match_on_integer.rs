//! Match is defined over text, so a match index on an integer does not
//! compile.
use stack_encrypt::target::{indexed, Borrowed, Match};
use stack_kms::FakeDataKeySource;

fn main() {
    let _ = indexed::<u32, FakeDataKeySource, Borrowed, _>(Match::default());
}
