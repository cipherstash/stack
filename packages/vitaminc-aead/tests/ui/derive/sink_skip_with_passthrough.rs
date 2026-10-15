//! A skipped field has no entry to pass through.

use vitaminc_aead::typed::Decrypt;

#[derive(Decrypt)]
struct Row {
    #[aead(skip, passthrough)]
    id: i64,
    ssn: String,
}

fn main() {}
