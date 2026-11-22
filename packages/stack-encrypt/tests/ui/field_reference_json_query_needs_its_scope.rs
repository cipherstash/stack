//! A JSON query of a record that lists a scope needs the scope before it
//! can be encrypted, as any field query does.
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
#[stash(struct = Customer, scope = "customers", scope(tenant: u64))]
struct EncryptedCustomer {
    profile: JsonDocument,
}

async fn query(cipher: StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let _ = EncryptedCustomer::PROFILE
        .contains(serde_json::json!({"a": 1}))
        .encrypt(&keyset);
}

fn main() {}
