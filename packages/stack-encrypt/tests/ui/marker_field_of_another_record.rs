//! A record field's marker reaches the markers of the record it holds and
//! no other: a marker of another record would derive under a context no
//! stored value has. The inner record must list no scope of its own,
//! since a query of it would take two.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct Address {
    street: String,
}

#[derive(Clone, Zeroize)]
struct Office {
    tenant: u64,
    street: String,
}

#[derive(Clone, Zeroize)]
struct Account {
    email: String,
    address: Address,
    office: Office,
}

#[derive(EncryptTarget)]
#[stash(struct = Address, scope = "addresses")]
struct EncryptedAddress {
    street: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Office, scope = "offices", scope(field = "tenant"))]
struct EncryptedOffice {
    #[stash(passthrough)]
    tenant: u64,
    street: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    email: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
    office: EncryptedOffice,
}

fn main() {
    let _ = EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET);
    // A marker of the outer record, not of the record the field holds.
    let _ = EncryptedAccount::ADDRESS.field(EncryptedAccount::EMAIL);
    // The inner record stores a scope of its own.
    let _ = EncryptedAccount::OFFICE.field(EncryptedOffice::STREET);
}
