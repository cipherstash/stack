//! `skip` and `take` belong to the sink derives; the legacy `Encrypt` and
//! `Decrypt` derives refuse them rather than silently keep the field.

use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(skip)]
    id: i64,
    ssn: String,
}

fn main() {}
