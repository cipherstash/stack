//! A document field has an accessor for each path its `ordered = {..}`
//! declares and nothing else: a path or a member it does not declare, and
//! an `elements()` accessor for a path that is not an array, do not
//! compile. A field that declares no paths has no `at()` or `elements()`:
//! it names its paths as text.
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
    #[stash(json(ordered = { "$.age": u32, "$.visits[*].place": String }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct UndeclaredCustomer {
    profile: JsonDocument,
}

fn main() {
    // A path the field does not declare.
    let _ = EncryptedCustomer::PROFILE.at().email();
    // A member the array does not declare.
    let _ = EncryptedCustomer::PROFILE.elements().visits().at();
    // A path that is not an array.
    let _ = EncryptedCustomer::PROFILE.elements().age();
    // A field that declares no paths.
    let _ = UndeclaredCustomer::PROFILE.at();
    let _ = UndeclaredCustomer::PROFILE.elements();
}
