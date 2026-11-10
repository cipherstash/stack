//! A query takes a scope and no binding: a binding is not in the query
//! context, so a query chain cannot be extended by a bare one. A binding
//! inside a `CallerContext` or a `DeclaredContext` converts, and is refused
//! when the query is awaited (`PlanError::BindInQuery`,
//! `tests/scopes_and_bindings.rs`).
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::target::{Bind, Scope};
use stack_encrypt::{op, Equality, Plan, StackCipher};

struct User {
    email: String,
}

async fn query(cipher: &StackCipher<FakeDataKeySource>, plan: &Plan<User, FakeDataKeySource>) {
    let field = plan.field("email").unwrap();
    // A scope extends the query's context.
    let _ = cipher
        .query(op::Eq, "ada@example.com")
        .extend(Scope::new(42u64))
        .on(&field)
        .await;
    // A binding does not.
    let _ = cipher
        .query(op::Eq, "ada@example.com")
        .extend(Bind::new(9u128))
        .on(&field)
        .await;
}

fn main() {
    let _ = Equality;
}
