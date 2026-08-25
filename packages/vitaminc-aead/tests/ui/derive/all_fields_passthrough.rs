// Nothing would be encrypted, so the container would carry no tag at all:
// neither the associated data nor the entry keys would be authenticated.
// `MapCipher::end` refuses to seal one, so the derive refuses to emit it.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(passthrough)]
    id: i64,
    #[aead(passthrough)]
    tenant: String,
}

fn main() {}
