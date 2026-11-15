//! An element-scoped predicate holds at least one condition: `elements`
//! alone has no `encrypt`, so an empty predicate, which no element could
//! satisfy, does not compile.
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipher;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    #[stash(json(ordered = ["$.visits[*].at"]))]
    profile: JsonDocument,
}

async fn query(cipher: StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let _ = EncryptedCustomer::PROFILE
        .elements("$.visits[*]")
        .encrypt(&keyset);
}

fn main() {}
