//! The shared contract suite, run against the static key backend and the
//! in-memory fake vendor.

use stack_encrypt::kms::KeyVendor;
use stack_kms_vendor::contract;
use stack_kms_vendor::{FakeVendor, StaticKeyVendor};
use vitaminc::protected::Protected;

#[tokio::test]
async fn the_static_key_backend_meets_the_contract() {
    contract::run(
        || StaticKeyVendor::new("dev-key/v1", Protected::new([0x11u8; 32])),
        "dev-key/v1",
    )
    .await;
}

#[tokio::test]
async fn the_fake_vendor_meets_the_contract() {
    for vendor in [KeyVendor::Aws, KeyVendor::Vault] {
        contract::run(|| FakeVendor::new(vendor), FakeVendor::KEY_REF).await;
    }
}
