//! A condition goes on a member of the array the predicate is on. After a
//! condition, `and()` gives that array's members and no other array's, so
//! a member of another array does not compile.
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
    #[stash(json(ordered = {
        "$.visits[*].place": String,
        "$.orders[*].total": f64,
    }))]
    profile: JsonDocument,
}

fn main() {
    let _ = EncryptedCustomer::PROFILE
        .elements()
        .visits()
        .place()
        .eq("home")
        .and()
        .total();
    let _ = EncryptedCustomer::PROFILE.elements().orders().place();
}
