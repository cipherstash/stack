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
    #[stash(json(
        ordered = { "$.age": u32, "$.visits[*].place": String, "$.balance": i16 },
        paths = { "$.score": f64 }
    ))]
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
    // A number the path's type does not hold: a fraction, a number below
    // zero and one past the type's range.
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age > 1.5");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age >= -1");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.age == 4294967296");
    let _ = predicate!(EncryptedCustomer::PROFILE, "$.balance < -32769");
    // And the numbers it does hold, which compile: each type's limits, and
    // any number for an `f64`.
    let _ = predicate!(
        EncryptedCustomer::PROFILE,
        "$.age == 0 && $.age <= 4294967295 && $.balance >= -32768 && $.balance <= 32767"
    );
    let _ = predicate!(
        EncryptedCustomer::PROFILE,
        "$.score == 1.5 || $.score == -3 || $.score == 18446744073709551615 || $.score == 1e3"
    );
}
