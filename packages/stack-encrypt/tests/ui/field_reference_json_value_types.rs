//! A JSON query's values are typed. A declared path takes the type its
//! `ordered = {..}` entry names ([`PathValue`]), at the path and for a
//! member of an array. A path named as text takes a number or a string for
//! an ordering ([`JsonOrdered`]) and a scalar for equality
//! ([`JsonScalar`]). An `f32` is neither: serde_json widens one when it
//! builds a document, so the caller passes the `f64` the document holds.
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
    #[stash(json(ordered = {
        "$.age": u32,
        "$.score": f64,
        "$.visits[*].at": u64,
        "$.visits[*].place": String,
    }))]
    profile: JsonDocument,
}

fn main() {
    // A declared path, and a member of a declared array.
    let _ = EncryptedCustomer::PROFILE.at().age().gt("thirty");
    let _ = EncryptedCustomer::PROFILE.at().age().eq(30i64);
    let _ = EncryptedCustomer::PROFILE.at().score().eq(0.1f32);
    let _ = EncryptedCustomer::PROFILE.elements().visits().place().eq(1);
    let _ = EncryptedCustomer::PROFILE.elements().visits().at().gt("noon");
    // A path named as text.
    let _ = EncryptedCustomer::PROFILE.at_text_path("$.age").gt(true);
    let _ = EncryptedCustomer::PROFILE
        .at_text_path("$.age")
        .eq(serde_json::json!({"a": 1}));
    let _ = EncryptedCustomer::PROFILE
        .elements_text_path("$.visits[*]")
        .gt("at", false);
    let _ = EncryptedCustomer::PROFILE.at_text_path("$.age").eq(0.1f32);
}
