//! The Azure backend against real Azure Key Vault and Managed HSM.
//!
//! Microsoft publishes no Key Vault emulator, so this is the only test of
//! the real service. It runs when `STACK_KMS_AZURE_LIVE_KEY` names a Key
//! Vault RSA key (`https://{vault}.vault.azure.net/keys/{name}`) and skips
//! itself otherwise. `STACK_KMS_AZURE_LIVE_HSM_KEY`, if set, names a
//! Managed HSM `oct-HSM` key that is tested the same way. The credentials
//! come from the environment
//! ([`DefaultCredentials`](stack_kms_azure::DefaultCredentials)): normally
//! `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` of a
//! service principal with "Key Vault Crypto Service Encryption User" on the
//! key.
//!
//! ```text
//! STACK_KMS_AZURE_LIVE_KEY=https://<vault>.vault.azure.net/keys/stack-kms-azure-live \
//! AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
//!   mise run test:live:stack-kms-azure
//! ```
//!
//! The opt-in `integration-azure-key-vault.yml` workflow runs it in CI.

use stack_kms::{BackendErrorKind, Error};
use stack_kms_azure::{wrapped_key_version, AzureKeyVault, KeyId};
use stack_kms_vendor::derive::wrapped_data_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn live_key(variable: &str) -> Option<String> {
    let key = std::env::var(variable).ok().filter(|key| !key.is_empty())?;
    assert!(
        KeyId::parse(&key).is_some(),
        "{variable} is not an Azure key identifier: {key}"
    );
    Some(key)
}

fn live_keys() -> Vec<String> {
    ["STACK_KMS_AZURE_LIVE_KEY", "STACK_KMS_AZURE_LIVE_HSM_KEY"]
        .into_iter()
        .filter_map(live_key)
        .collect()
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { vendor, kind, .. } => {
            assert_eq!(vendor, "azure-key-vault");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn azure_key_vault_meets_the_contract() {
    let keys = live_keys();
    if keys.is_empty() {
        eprintln!("skipped: set STACK_KMS_AZURE_LIVE_KEY to run against Azure Key Vault");
        return;
    }
    for key in keys {
        contract::run(|| AzureKeyVault::from_env().expect("credentials"), &key).await;
    }
}

#[tokio::test]
async fn azure_key_vault_binds_the_associated_data_and_maps_errors() {
    let keys = live_keys();
    if keys.is_empty() {
        eprintln!("skipped: set STACK_KMS_AZURE_LIVE_KEY to run against Azure Key Vault");
        return;
    }
    for key in keys {
        let kms = AzureKeyVault::from_env().expect("credentials");
        let id = Uuid::new_v4();
        let aad = wrapped_data_key_aad(id, &[3u8; 16], "users/email");
        let wrapped = kms
            .wrap(&key, &Protected::new([0x5Au8; 32]), &aad)
            .await
            .unwrap();
        assert!(wrapped_key_version(&wrapped).is_some());
        let opened = kms.unwrap(&key, &wrapped, &aad).await.unwrap();
        assert_eq!(opened.risky_ref(), &[0x5Au8; 32]);

        // Other associated data: Azure unwraps, the client refuses.
        let other = wrapped_data_key_aad(id, &[3u8; 16], "users/name");
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
            parsed.vault(),
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
