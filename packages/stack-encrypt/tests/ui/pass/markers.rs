//! Shapes a record's markers must compile in: a public record whose field
//! is a private nested record (the marker's constant names that type), a
//! raw-identifier field, a generic record, a field of four indexes whose
//! last answers equality, a nullable field with a query type, and a marker
//! reached through a record field.
#![deny(warnings)]
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreTerm};
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
    #[stash(query = String)]
    street: Encrypted<EqualityTerm>,
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

#[derive(Clone, Zeroize)]
pub struct Note {
    body: String,
    title: Option<String>,
    blob: String,
}

#[derive(EncryptTarget)]
#[stash(struct = Note, scope = "notes")]
pub struct EncryptedNote {
    body: Encrypted<(MatchTerms, OreTerm<String>, OpeTerm<String>, EqualityTerm)>,
    #[stash(query = String)]
    title: Option<Encrypted<EqualityTerm>>,
    blob: StackCipherText,
}

fn main() {
    let _ = EncryptedNote::BODY.eq("x");
    let _ = EncryptedNote::BODY.matches("x");
    let _ = EncryptedNote::TITLE.eq("x");
    let _ = EncryptedNote::TITLE.eq(&String::from("x"));
    let _ = EncryptedNote::BLOB;
    let _ = EncryptedAccount::ADDRESS
        .field(EncryptedAddress::STREET)
        .eq("x");
    let _ = EncryptedAccount::TYPE;
    let _ = EncryptedAccount::ADDRESS;
    let _ = EncryptedTagged::<String>::TAG;
}
