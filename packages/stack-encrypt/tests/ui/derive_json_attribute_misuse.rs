//! `json(..)` takes `ordered = {..}`, `names = {..}` and `sealed_root = ..`, once, and only
//! on a sealed field of a `struct = ..` record: a `plaintext` record's
//! field and a passthrough field have no field reference to query it with.
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::target::EncryptTarget;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct UnknownOption {
    #[stash(json(ordered = { "$.a": u32 }, depth = 3))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct GivenTwice {
    #[stash(json(ordered = { "$.a": u32 }), json(sealed_root = false))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(plaintext = JsonPlaintext)]
struct OfAPlaintextRecord {
    #[stash(json(ordered = { "$.a": u32 }))]
    profile: JsonDocument,
}

fn main() {}
