//! `predicate!` takes a field that stores a JSON document.
use stack_encrypt::predicate;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    name: String,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    name: StackCipherText,
}

fn main() {
    let _ = predicate!(EncryptedCustomer::NAME, "$.age >= 30");
}
