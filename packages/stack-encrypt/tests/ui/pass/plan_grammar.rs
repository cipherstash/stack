//! The widened plan grammar compiles in each of its spellings: the two
//! starts, a picker with a closure (through `pick`) and with a function, and
//! `encrypt_into` in both positions.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::plan::pick;
use stack_encrypt::sem::{EqualityTerm, MatchTerms};
use stack_encrypt::{Encrypted, Equality, Ore, Plan, StackCipherText};

struct User {
    email: String,
    age: u32,
}

fn age(u: &User) -> &u32 {
    &u.age
}

fn main() {
    let _ = Plan::fields::<User, FakeDataKeySource>()
        .context("users")
        .encrypt_into::<Encrypted<(EqualityTerm, MatchTerms)>, _>(pick("email", |u: &User| &u.email))
        .encrypt_index(("age", age), (Equality, Ore))
        .build();
    let _ = Plan::value::<String>()
        .encrypt_into::<(StackCipherText, EqualityTerm)>()
        .build();
    let _ = Plan::value::<u32>().context("users/age").with(Ore).build();
}
