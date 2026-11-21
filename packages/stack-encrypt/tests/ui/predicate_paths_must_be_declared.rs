//! Every path a predicate names is one its field declares, under `ordered`
//! or `paths`: a path the field does not declare, an ordering of a path
//! declared for equality alone, a filter condition on a member its array
//! does not order or on a member of another array, and any path of a field
//! that declares none, do not compile. Each refusal names the path.
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
    #[stash(json(ordered = {
        "$.age": u32,
        "$.visits[*].place": String,
        "$.contacts[*].calls": u32,
    }, paths = { "$.name": String, "$.visits[*].kind": String }))]
    profile: JsonDocument,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct UndeclaredCustomer {
    profile: JsonDocument,
}

fn main() {
    // A path the field does not declare.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.agee >= 30");
    // Equality on a path the field does not declare.
    let _ = predicate!(EncryptedCustomer::PROFILE, r#"$.email == "ada@example.com""#);
    // An ordering of a path declared for equality alone.
    let _ = predicate!(EncryptedCustomer::PROFILE, r#"$.name > "A""#);
    // A member declared for equality alone, in a filter of two conditions,
    // which compares each member by its ordering term.
    let _ = predicate!(
        EncryptedCustomer::PROFILE,
        r#"exists($.visits[*] ? (@.place == "home" && @.kind == "walk-in"))"#
    );
    // A member its array does not declare.
    let _ = predicate!(
        EncryptedCustomer::PROFILE,
        r#"exists($.visits[*] ? (@.place == "home" && @.at > 10))"#
    );
    // A member of another array.
    let _ = predicate!(
        EncryptedCustomer::PROFILE,
        r#"exists($.visits[*] ? (@.place == "home" && @.calls > 5))"#
    );
    // A field that declares no paths.
    let _ = predicate!(UndeclaredCustomer::PROFILE, "$.age >= 30");
}
