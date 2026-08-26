// A newtype's value is not stored under a map key, so there is no key to
// rename. Ignoring the attribute would leave the author believing the value is
// key-bound when nothing binds it.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Token(#[aead(rename = "token")] String);

fn main() {}
