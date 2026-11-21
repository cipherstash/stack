//! `ordered = {..}` maps each path to the type of its values. The derive
//! parses every path with the engine's grammar and refuses, at the path: a
//! path that does not parse, a path with no `$`, an array position, a path
//! given twice, a key that gives no accessor name, and two paths that give
//! one name. The old list form and an entry with no type are refused too.
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::target::EncryptTarget;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct NotAPath {
    #[stash(json(ordered = { "$.visits[": u64 }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct NoRoot {
    #[stash(json(ordered = { "age": u32 }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct APosition {
    #[stash(json(ordered = { "$.visits[2].at": u64 }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct GivenTwice {
    #[stash(json(ordered = { "$.age": u32, "$[\"age\"]": u32 }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct NeedsAName {
    #[stash(json(ordered = { "$[\"ship to\"]": String }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct OneName {
    #[stash(json(ordered = { "$.ship_to": String, "$.ship.to": String }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct AListOfPaths {
    #[stash(json(ordered = ["$.age"]))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct NoType {
    #[stash(json(ordered = { "$.age" }))]
    profile: JsonDocument,
}

fn main() {}
