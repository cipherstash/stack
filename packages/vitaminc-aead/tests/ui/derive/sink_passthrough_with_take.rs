//! A passthrough field is lent to the sink, never taken out of `self`.

use vitaminc_aead::Encrypt;

#[derive(Encrypt)]
struct Row {
    #[aead(passthrough, take)]
    tenant: String,
    ssn: String,
}

fn main() {}
