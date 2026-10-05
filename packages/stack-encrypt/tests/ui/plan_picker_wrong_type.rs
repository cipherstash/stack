//! A picker's accessor names the field's type, so a verb that names another
//! type for the same field does not compile.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::plan::pick;
use stack_encrypt::{Equality, Plan};

struct User {
    email: String,
}

fn main() {
    let _ = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .encrypt_index::<u32>(pick("email", |u: &User| &u.email), Equality);
}
