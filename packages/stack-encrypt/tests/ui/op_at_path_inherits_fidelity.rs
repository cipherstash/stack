//! An accessor is held to its leaf's requirement: `AtPath<Matches>` needs a
//! probabilistic term, as `Matches` does, so an exact term cannot answer it.
use stack_encrypt::op::{self, TermFor};
use stack_encrypt::sem::EqualityTerm;

fn answers<Op: op::Operator, T: TermFor<Op>>() {}

fn main() {
    answers::<op::AtPath<op::Matches>, EqualityTerm>();
}
