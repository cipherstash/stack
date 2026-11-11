//! A record field's marker reaches the markers of the record it holds and
//! no other: a marker of another record would derive under a context no
//! stored value has. A nullable record field is the same.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct Address {
    street: String,
}

#[derive(Clone, Zeroize)]
struct Account {
    email: String,
    address: Address,
    second: Option<Address>,
}

#[derive(EncryptTarget)]
#[stash(struct = Address, scope = "addresses")]
struct EncryptedAddress {
    street: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    email: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
    second: Option<EncryptedAddress>,
}

fn main() {
    let _ = EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET);
    // A marker of the outer record, not of the record the field holds.
    let _ = EncryptedAccount::ADDRESS.field(EncryptedAccount::EMAIL);
    let _ = EncryptedAccount::SECOND.field(EncryptedAddress::STREET);
    // A marker of the outer record, on a nullable record field.
    let _ = EncryptedAccount::SECOND.field(EncryptedAccount::EMAIL);
}
