//! The Azure backend against a real Azure Key Vault Managed HSM.
//!
//! **Not run yet.** We have no live Managed HSM, so this test has never
//! run, and its workflow (`integration-azure-managed-hsm.yml`) stays off:
//! do not set `STACK_KMS_AZURE_LIVE_KEY` until an instance is available.
//!
//! Microsoft publishes no Managed HSM emulator, so this is the only test of
//! the real service. It runs when `STACK_KMS_AZURE_LIVE_KEY` names a Managed
//! HSM `oct-HSM` key (`https://{hsm}.managedhsm.azure.net/keys/{name}`) and
//! skips itself otherwise. The credentials come from the environment
//! ([`DefaultCredentials`](stack_kms_azure::DefaultCredentials)): normally
//! `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` of a
//! service principal with "Managed HSM Crypto Service Encryption User" on
//! the key.
//!
//! ```text
//! STACK_KMS_AZURE_LIVE_KEY=https://<hsm>.managedhsm.azure.net/keys/stack-kms-azure-live \
//! AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
//!   mise run test:live:stack-kms-azure
//! ```

use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_azure::{wrapped_key_version, AzureManagedHsm, KeyId};
use stack_kms_vendor::derive::record_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn live_keys() -> Vec<String> {
    let variable = "STACK_KMS_AZURE_LIVE_KEY";
    let Some(key) = std::env::var(variable).ok().filter(|key| !key.is_empty()) else {
        return Vec::new();
    };
    assert!(
        KeyId::parse(&key).is_some(),
        "{variable} is not a Managed HSM key identifier: {key}"
    );
    vec![key]
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { backend, kind, .. } => {
            assert_eq!(backend.name(), "azure-managed-hsm");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn azure_managed_hsm_meets_the_contract() {
    let keys = live_keys();
    if keys.is_empty() {
        eprintln!("skipped: set STACK_KMS_AZURE_LIVE_KEY to run against Azure Managed HSM");
        return;
    }
    for key in keys {
        contract::run(|| AzureManagedHsm::from_env().expect("credentials"), &key).await;
    }
}

#[tokio::test]
async fn azure_managed_hsm_binds_the_associated_data_and_maps_errors() {
    let keys = live_keys();
    if keys.is_empty() {
        eprintln!("skipped: set STACK_KMS_AZURE_LIVE_KEY to run against Azure Managed HSM");
        return;
    }
    for key in keys {
        let kms = AzureManagedHsm::from_env().expect("credentials");
        let id = Uuid::new_v4();
        let aad = record_key_aad(id, KeyVendor::Azure, KeyMode::Derived);
        let wrapped = kms
            .wrap(&key, &Protected::new([0x5Au8; 32]), &aad)
            .await
            .unwrap();
        assert!(wrapped_key_version(&wrapped).is_some());
        let opened = kms.unwrap(&key, &wrapped, &aad).await.unwrap();
        assert_eq!(opened.risky_ref(), &[0x5Au8; 32]);

        // Other associated data (the root key of another keyset): Azure
        // unwraps, the client refuses.
        let other = record_key_aad(Uuid::new_v4(), KeyVendor::Azure, KeyMode::Derived);
        let error = kms.unwrap(&key, &wrapped, &other).await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);

        // A damaged ciphertext.
        let mut damaged = wrapped.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0x01;
        let error = kms.unwrap(&key, &damaged, &aad).await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);

        // A key that does not exist.
        let parsed = KeyId::parse(&key).unwrap();
        let missing = format!(
            "{}/keys/stack-kms-azure-no-such-key-{}",
            parsed.hsm(),
            Uuid::new_v4().simple()
        );
        let error = kms
            .wrap(&missing, &Protected::new([1u8; 32]), &aad)
            .await
            .unwrap_err();
        let kind = kind_of(error);
        assert!(
            matches!(
                kind,
                BackendErrorKind::NotFound | BackendErrorKind::AccessDenied
            ),
            "{kind:?}"
        );
    }
}
