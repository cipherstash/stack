//! The index sets that must compile: one index, tuples of two to five, a
//! default and a configured match index, over the plaintexts each is
//! defined for, in either source mode.
use stack_encrypt::sem::{MatchConfig, MatchOptions};
use stack_encrypt::target::{indexed, Borrowed, Equality, Match, Ope, Ore, Owned};
use stack_kms::FakeDataKeySource;

struct Words;
impl MatchConfig for Words {
    fn options() -> MatchOptions {
        MatchOptions::default()
    }
}

fn main() {
    let _ = indexed::<u32, FakeDataKeySource, Borrowed, _>(Equality);
    let _ = indexed::<u32, FakeDataKeySource, Borrowed, _>((Equality, Ore));
    let _ = indexed::<u32, FakeDataKeySource, Owned, _>((Equality, Ore, Ope));
    let _ = indexed::<String, FakeDataKeySource, Borrowed, _>(Match::default());
    let _ = indexed::<String, FakeDataKeySource, Borrowed, _>((
        Equality,
        Match::<Words>::new(),
        Ore,
        Ope,
    ));
    let _ = indexed::<String, FakeDataKeySource, Owned, _>((
        Equality,
        Match::default(),
        Ore,
        Ope,
        Match::<Words>::new(),
    ));
}
