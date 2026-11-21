//! A value compared with a path is of the path's type: a variable's
//! value, refused at the value, and a literal in the text, refused at the
//! predicate.
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
    #[stash(json(ordered = { "$.age": u32, "$.visits[*].place": String }))]
    profile: JsonDocument,
}

fn main() {
    // A variable of another type.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >= $min", min = "thirty");
    let place = 7_u8;
    let _ = predicate!(
        EncryptedCustomer::PROFILE,
        "exists($.visits[*] ? (@.place == $place))",
        place
    );
    // A literal of another type.
    let _ = predicate!(EncryptedCustomer::PROFILE, r#"$.age > "x""#);
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.visits[*].place == 3");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age == true");
}
