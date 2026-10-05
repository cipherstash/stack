//! Selecting an index from a set that holds it twice does not compile: its
//! place in the set is ambiguous, so `At` cannot be inferred.
use stack_encrypt::target::{Equality, Indexes};

fn main() {
    let indexes = (Equality, Equality);
    let _ = Indexes::<u32>::select::<Equality, _>(&indexes);
}
