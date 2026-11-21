//! A JSON query's values are typed: an ordering takes a number or a
//! string ([`JsonOrdered`]), and equality at a path a scalar
//! ([`JsonScalar`]). A boolean orders nothing, a document is not a
//! scalar, and an `f32` is neither: serde_json widens one when it builds a
//! document, so the caller passes the `f64` the document holds.
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
    #[stash(json(ordered = ["$.age", "$.visits[*].at"]))]
    profile: JsonDocument,
}

fn main() {
    let _ = EncryptedCustomer::PROFILE.at("$.age").gt(true);
    let _ = EncryptedCustomer::PROFILE.at("$.age").eq(serde_json::json!({"a": 1}));
    let _ = EncryptedCustomer::PROFILE.elements("$.visits[*]").gt("at", false);
    let _ = EncryptedCustomer::PROFILE.at("$.age").eq(0.1f32);
}
