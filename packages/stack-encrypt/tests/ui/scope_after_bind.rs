//! A binding comes after every scope. There is no method that adds a scope
//! after a binding, so the order is fixed by the types.
use stack_encrypt::target::{Bind, Scope};

fn main() {
    let _ = Bind::new(9u128).scope(42u64);
    let _ = Scope::new(42u64).bind(9u128).scope(7u64);
}
