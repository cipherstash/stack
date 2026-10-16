// A newtype is transparent — no map is opened — so there is no entry for a
// passthrough to occupy. Honouring it would leave the whole value unencrypted.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Token(#[aead(passthrough)] String);

fn main() {}
