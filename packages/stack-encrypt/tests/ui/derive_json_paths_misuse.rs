//! `paths = {..}` takes the path grammar and the rules `ordered` takes, and
//! a type equality compares: a path given under both keys, a position, a
//! repeated path, and a type no path holds do not compile.
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::target::EncryptTarget;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct BothKeys {
    #[stash(json(ordered = { "$.age": u32 }, paths = { "$.age": u32 }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct Position {
    #[stash(json(paths = { "$.tags[0]": String }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct Twice {
    #[stash(json(paths = { "$.name": String, "$.name": String }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct NotAScalar {
    #[stash(json(paths = { "$.tags": Vec<String> }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct OrderedBoolean {
    #[stash(json(ordered = { "$.vip": bool }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct Collision {
    #[stash(json(ordered = { "$.first_name": String }, paths = { "$.firstName": String }))]
    profile: JsonDocument,
}

fn main() {}
