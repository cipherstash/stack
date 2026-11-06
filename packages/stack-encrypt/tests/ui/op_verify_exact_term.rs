//! An exact query term has nothing to verify: the server's answer is the
//! answer, so `verify` on an equality term does not compile.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::{self, Probabilistic};
use stack_encrypt::{Equality, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let plan = Plan::context("users/email")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let term = cipher.query(op::Eq, "bob").on(&plan).await.unwrap();
    let _ = term.verify("bob");
}

fn main() {}
