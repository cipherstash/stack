//! The default match index folds case, so it answers only a
//! case-insensitive `Matches`: asking it for a case-sensitive one does not
//! compile, rather than quietly folding the query.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{op, Match, Plan, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let name_plan = Plan::context("users/name")
        .with::<String, _>(Match)
        .build()
        .unwrap();
    let _ = cipher
        .query(op::Matches.case_sensitive(), "Ali")
        .via(Match)
        .on(&name_plan);
}

fn main() {}
