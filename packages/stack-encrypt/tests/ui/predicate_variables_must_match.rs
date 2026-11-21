//! Every `$name` the text uses is given, every variable given is used, and
//! none is given twice.
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::predicate;
use stack_encrypt::target::EncryptTarget;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    #[stash(json(ordered = { "$.age": u32 }))]
    profile: JsonDocument,
}

fn main() {
    // A variable the text uses and no value for it.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >= $min");
    // A variable given and not used.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >= $min", min = 30, limit = 5);
    // A variable given twice.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >= $min", min = 30, min = 40);
}
