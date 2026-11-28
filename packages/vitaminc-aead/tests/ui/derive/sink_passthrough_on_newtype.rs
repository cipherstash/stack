// A newtype is transparent — no map is opened — so there is no entry for a
// passthrough to occupy. Honouring it would leave the whole value unencrypted.
// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Token(#[aead(passthrough)] String);

fn main() {}
