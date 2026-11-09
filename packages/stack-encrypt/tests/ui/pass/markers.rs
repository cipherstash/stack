//! Shapes a record's markers must compile in: a public record whose field
//! is a private nested record (the marker's constant names that type), a
//! raw-identifier field, and a generic record.
#![deny(warnings)]
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{Encrypted, StackCipherText};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct Address {
    street: String,
}

#[derive(Clone, Zeroize)]
pub struct Account {
    r#type: String,
    address: Address,
}

#[derive(EncryptTarget)]
#[stash(struct = Address, scope = "addresses")]
struct EncryptedAddress {
    street: StackCipherText,
}

#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
pub struct EncryptedAccount {
    r#type: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
}

#[derive(Zeroize)]
pub struct Tagged<T: Zeroize> {
    tag: String,
    extra: T,
}

#[derive(EncryptTarget)]
#[stash(struct = Tagged<T>, scope = "tags")]
pub struct EncryptedTagged<T: Zeroize + Clone + Send + 'static> {
    tag: Encrypted<EqualityTerm>,
    #[stash(passthrough)]
    extra: T,
}

fn main() {
    let _ = EncryptedAccount::TYPE;
    let _ = EncryptedAccount::ADDRESS;
    let _ = EncryptedTagged::<String>::TAG;
}
