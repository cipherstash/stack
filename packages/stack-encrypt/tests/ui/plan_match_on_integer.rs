//! Match is defined over text, so a plan cannot declare a match index on an
//! integer field.
use stack_encrypt::plan::{Field, Fields};
use stack_encrypt::{Match, Plan};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

struct User {
    age: u32,
}
impl Fields for User {
    fn field_names(&self) -> Vec<&str> {
        vec!["age"]
    }
}
impl Field<u32> for User {
    fn field(&self, name: &str) -> Option<&u32> {
        (name == "age").then_some(&self.age)
    }
}

fn main() {
    let _ = Plan::context("users")
        .fields::<User, FakeKeysetRegistry>()
        .encrypt_index::<u32>("age", Match::default());
}
