//! `predicate!` reads its text with the engine's grammar when the program
//! compiles: text that does not parse, and a construct the JSON index
//! cannot answer whatever the variables hold, do not compile. Each refusal
//! names the construct and its byte offset.
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
    #[stash(json(ordered = { "$.age": u32, "$.visits[*].place": String, "$.tags[*]": String }))]
    profile: JsonDocument,
}

fn main() {
    // Text that does not parse.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age = 30");
    // Constructs the index cannot answer.
    let _ = predicate!(EncryptedCustomer::PROFILE, r#"$.age like_regex "^3""#);
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age + 1 > 30");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.visits[2].place == \"home\"");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.tags[*] != \"x\"");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.tags[*] > \"x\"");
    let _ = predicate!(EncryptedCustomer::PROFILE, "exists($.age ? (@ == 1))");
    let _ = predicate!(EncryptedCustomer::PROFILE, "exists($.visits[*] ? (@ > 1 && @.place == \"x\"))");
    // A literal the engine refuses whatever the field declares.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >= null");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age == 1e999");
}
