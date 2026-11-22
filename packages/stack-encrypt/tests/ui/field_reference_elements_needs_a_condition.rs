//! An element-scoped predicate holds at least one condition: an array
//! alone, declared or named as text, has no `encrypt`, so an empty
//! predicate, which no element could satisfy, does not compile.
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
    #[stash(json(ordered = { "$.visits[*].at": u64 }))]
    profile: JsonDocument,
}

async fn query(cipher: StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let _ = EncryptedCustomer::PROFILE.elements().visits().encrypt(&keyset);
    let _ = EncryptedCustomer::PROFILE
        .elements_text_path("$.visits[*]")
        .encrypt(&keyset);
}

fn main() {}
