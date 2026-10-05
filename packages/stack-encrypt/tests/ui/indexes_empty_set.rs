//! `()` is not a set of indexes: an indexed field with no index would be a
//! ciphertext-only field that says otherwise. That field is `ciphertext()`.
use stack_encrypt::target::{indexed, Borrowed};
use stack_kms::FakeDataKeySource;

fn main() {
    let _ = indexed::<u32, FakeDataKeySource, Borrowed, _>(());
}
