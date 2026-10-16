//! Two variants with one discriminant would be stored as the same value.

use vitaminc_aead::Decrypt;

#[derive(Decrypt)]
enum Status {
    Active = 1,
    Suspended = 0,
    Closed,
}

fn main() {}
