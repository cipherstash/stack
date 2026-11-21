//! A predicate variable is a scalar ([`JsonScalar`]), as a path's `eq`
//! takes: a document or an array does not compile, and neither does an
//! `f32`.
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::target::EncryptTarget;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    profile: JsonDocument,
}

fn main() {
    let _ = EncryptedCustomer::PROFILE
        .predicate("$.age >= $min")
        .var("min", serde_json::json!({"a": 1}));
    let _ = EncryptedCustomer::PROFILE
        .predicate("$.age >= $min")
        .var("min", vec![30]);
    let _ = EncryptedCustomer::PROFILE
        .predicate("$.age >= $min")
        .var("min", 0.5f32);
}
