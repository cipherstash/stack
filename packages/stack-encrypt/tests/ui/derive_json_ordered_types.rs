//! An ordered path holds a number or a string, so its type is an integer
//! type, `f64` or `String` ([`JsonPathType`]). A boolean, an `f32` and a
//! container are refused at the type.
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
        "$.active": bool,
        "$.score": f32,
        "$.visits[*].tags": Vec<String>,
    }))]
    profile: JsonDocument,
}

fn main() {}
