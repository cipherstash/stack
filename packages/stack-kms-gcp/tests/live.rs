//! The Cloud KMS backend against real Google Cloud KMS.
//!
//! Google publishes no Cloud KMS emulator, so this is the only test of the
//! real service. It runs when `STACK_KMS_GCP_LIVE_KEY` names a symmetric
//! `ENCRYPT_DECRYPT` crypto key
//! (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`) and skips
//! itself otherwise. The credentials come from the environment
//! ([`DefaultCredentials`](stack_kms_gcp::DefaultCredentials)): normally
//! `GOOGLE_APPLICATION_CREDENTIALS`, the path of a service account key file
//! with `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
//!
//! ```text
//! STACK_KMS_GCP_LIVE_KEY=projects/.../cryptoKeys/stack-kms-gcp-live \
//! GOOGLE_APPLICATION_CREDENTIALS=$HOME/stack-kms-gcp-live.json \
//!   mise run test:live:stack-kms-gcp
//! ```
//!
//! The opt-in `integration-gcp-kms.yml` workflow runs it in CI.

use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_gcp::{parse_key_name, wrapped_key_version, GcpKms};
use stack_kms_vendor::derive::{record_key_aad, wrapped_data_key_aad};
use stack_kms_vendor::{contract, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn live_key() -> Option<String> {
    let key = std::env::var("STACK_KMS_GCP_LIVE_KEY")
        .ok()
        .filter(|key| !key.is_empty())?;
    assert!(
        matches!(parse_key_name(&key), Some((_, None))),
        "STACK_KMS_GCP_LIVE_KEY is not a crypto key name: {key}"
    );
    Some(key)
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { vendor, kind, .. } => {
            assert_eq!(vendor, "gcp-kms");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn cloud_kms_meets_the_contract() {
    let Some(key) = live_key() else {
        eprintln!("skipped: set STACK_KMS_GCP_LIVE_KEY to run against Cloud KMS");
        return;
    };
    contract::run(|| GcpKms::from_env().expect("credentials"), &key).await;
}

#[tokio::test]
async fn cloud_kms_binds_the_associated_data_and_maps_errors() {
    let Some(key) = live_key() else {
        eprintln!("skipped: set STACK_KMS_GCP_LIVE_KEY to run against Cloud KMS");
        return;
    };
    let kms = GcpKms::from_env().expect("credentials");
    let id = Uuid::new_v4();
    let aad = wrapped_data_key_aad(id, &[3u8; 16], "users/email");
    let wrapped = kms
        .wrap(&key, &Protected::new([0x5Au8; 32]), &aad)
        .await
        .unwrap();
    assert!(wrapped_key_version(&wrapped).is_some_and(|version| version >= 1));
    let opened = kms.unwrap(&key, &wrapped, &aad).await.unwrap();
    assert_eq!(opened.risky_ref(), &[0x5Au8; 32]);

    // Other associated data.
    let other = record_key_aad(id, KeyVendor::Gcp, KeyMode::Wrapped);
    let error = kms.unwrap(&key, &wrapped, &other).await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);

    // A damaged ciphertext.
    let mut damaged = wrapped.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    let error = kms.unwrap(&key, &damaged, &aad).await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);

    // A key that does not exist. Cloud KMS answers PERMISSION_DENIED, not
    // NOT_FOUND, when the caller may not list the key ring, so either is
    // right here.
    let (name, _) = parse_key_name(&key).unwrap();
    let missing = format!(
        "{}/stack-kms-gcp-no-such-key-{}",
        name.rsplit_once('/').unwrap().0,
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
