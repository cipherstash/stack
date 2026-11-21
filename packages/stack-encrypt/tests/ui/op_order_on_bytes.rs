//! The ordering operators are answered over the integer types, the floats and text.
//! Bytes have no order key the ordering operators compare, so an ordering on
//! a bytes field does not compile, even where the field declares an ORE index.
use stack_encrypt::sem::OreTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct File {
    blob: Vec<u8>,
}

#[derive(EncryptTarget)]
#[stash(struct = File, scope = "files")]
struct EncryptedFile {
    blob: Encrypted<OreTerm<Vec<u8>>>,
}

fn main() {
    let _ = EncryptedFile::BLOB.lt(vec![1u8, 2]);
}
