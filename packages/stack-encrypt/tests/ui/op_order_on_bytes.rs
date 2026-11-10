//! The ordering operators are answered over the integer types, the floats and text.
//! Bytes have no order key the ordering operators compare, so an ordering
//! query over bytes does not compile, even when it names an ORE index. A
//! plan cannot declare that index on bytes at all (`order_index_on_bytes.rs`),
//! so the query names it with `via`.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op;
use stack_encrypt::{Ore, StackCipher};

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let _ = cipher
        .query(op::Lt, &vec![1u8, 2])
        .context("users/blob")
        .via(Ore);
}

fn main() {}
