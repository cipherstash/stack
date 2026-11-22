//! A path declared under `paths = {..}` has equality and no ordering: an
//! ordering, a range, and a value of another type do not compile.
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
    #[stash(json(ordered = { "$.age": u32 }, paths = { "$.name": String, "$.vip": bool }))]
    profile: JsonDocument,
}

fn main() {
    // Equality and the selector compile.
    let _ = EncryptedCustomer::PROFILE.at().name().eq("Ada");
    let _ = EncryptedCustomer::PROFILE.at().vip().eq(true);
    let _ = EncryptedCustomer::PROFILE.at().name().selector();
    // An ordering of a path that is not ordered.
    let _ = EncryptedCustomer::PROFILE.at().name().gt("A");
    let _ = EncryptedCustomer::PROFILE.at().name().between("A", "M");
    // A value of another type.
    let _ = EncryptedCustomer::PROFILE.at().vip().eq("yes");
}
