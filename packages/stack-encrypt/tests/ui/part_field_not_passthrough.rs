//! A part stored in the row names a `passthrough` field: the engine reads
//! it from the plaintext on encrypt and from the row on decrypt, so a field
//! the record does not pass through cannot hold it.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    tenant: u64,
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", scope(field = "tenant"))]
struct StoredTenant {
    email: Encrypted<EqualityTerm>,
}

fn main() {}
