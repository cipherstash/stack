//! A plan field declared with indexes needs at least one: `()` is not a set
//! of indexes. A field with no index is `encrypt(name)`.
use stack_encrypt::plan::{Field, Fields};
use stack_encrypt::Plan;
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
        .encrypt_index::<u32>("age", ());
}
