//! `JoinContext` is sealed: the pairs this crate joins are the only ones,
//! so a crate cannot add a join for its own context.
use stack_encrypt::target::{AeadContext, JoinContext};

#[derive(Clone)]
struct MyContext;

impl JoinContext<MyContext> for AeadContext {
    type Output = MyContext;
}

fn main() {}
