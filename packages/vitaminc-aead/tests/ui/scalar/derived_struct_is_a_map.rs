//! A derived struct walks as a map, one leaf per field, so it is not a
//! `Scalar` even with a single field.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;
use vitaminc_aead::Scalar;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Account {
    id: u64,
}

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    seals_one_leaf(Account { id: 1 });
}
