// A misspelt attribute is rejected rather than ignored: a silently dropped
// option is one the author believes is in effect.
// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Row {
    #[aead(passthru)]
    tenant: String,
    ssn: String,
}

fn main() {}
