// A misspelt attribute is rejected rather than ignored: a silently dropped
// option is one the author believes is in effect.
use vitaminc_aead::{Decrypt, Plaintext};

#[derive(Plaintext, Decrypt)]
struct Row {
    #[aead(passthru)]
    tenant: String,
    ssn: String,
}

fn main() {}
