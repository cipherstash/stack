//! `stack-encrypt` running end to end with AWS KMS as the key provider
//! instead of ZeroKMS.
//!
//! The chain is three pieces, and none of them is specific to this demo:
//!
//! - `vitaminc_kms::AwsDataKeySource<32>`: a data key source bound to one
//!   AWS KMS key. It is a `vitaminc-kms` `KeyProvider<32>`.
//! - `FixedIndexKeySource`: pairs that source with the persisted `KeyId` of
//!   the keyset's index key, so it is also an `IndexKeyProvider<32>`.
//! - `StaticKeysetRegistry`: stack-encrypt's registry over a fixed table of
//!   keysets. Here the table has one keyset, which is the default.
//!
//! `StackCipher` is then built over that registry exactly as it is over
//! ZeroKMS.
//!
//! Run it against LocalStack:
//!
//! ```sh
//! docker compose -f examples/aws-kms-demo/docker-compose.yml up -d
//! cd examples/aws-kms-demo && mise x -- cargo run
//! ```
//!
//! See README.md for the environment variables, for how to run it against a
//! real AWS account, and for how the index key's `KeyId` is provisioned.

use std::error::Error;

use aws_sdk_kms::error::{DisplayErrorContext, SdkError};
use stack_encrypt::registry::{FixedIndexKeySource, KeyId, StaticKeyset, StaticKeysetRegistry};
use stack_encrypt::{nonempty, StackCipherBuilder};
use uuid::Uuid;
use vitaminc_kms::{AwsDataKeySource, GenerateDataKey};

/// AES-256, the only data key size stack-encrypt uses.
const KEY_SIZE: usize = 32;

/// The keyset's id. Every leaf sealed under the keyset carries it, so a real
/// deployment chooses it once and keeps it with the keyset's configuration.
const KEYSET_ID: Uuid = Uuid::from_u128(0x6177_732d_6b6d_732d_6465_6d6f_0000_0001);

const LOCALSTACK: &str = "http://localhost:4566";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(client) = build_client().await? else {
        println!("LocalStack is not running on {LOCALSTACK}; skipping. See README.md.");
        return Ok(());
    };

    // An index KeyId is a data key that one AWS KMS key encrypted. With no
    // key named, the demo would create a new one, which cannot decrypt it.
    if env("AWS_KMS_DEMO_INDEX_KEY_ID").is_some() && env("AWS_KMS_DEMO_KEY_ID").is_none() {
        return Err(
            "AWS_KMS_DEMO_INDEX_KEY_ID needs the AWS_KMS_DEMO_KEY_ID it was made under".into(),
        );
    }

    // The AWS KMS key the keyset is bound to.
    let kms_key_id = match env("AWS_KMS_DEMO_KEY_ID") {
        Some(key_id) => key_id,
        None => {
            let key_id = create_symmetric_key(&client).await?;
            println!("created AWS KMS key {key_id}");
            key_id
        }
    };
    let source = AwsDataKeySource::<KEY_SIZE>::new(client, kms_key_id.clone());

    // The index key's `KeyId`. Provisioned once per keyset and then read
    // back on every run: a new one makes every earlier index term
    // unfindable. See README.md.
    let index_key_id = match env("AWS_KMS_DEMO_INDEX_KEY_ID") {
        Some(hex) => KeyId::new(unhex(&hex)?),
        None => {
            let key_id = source.generate_data_key().await?.key_id;
            println!(
                "provisioned an index key. To keep this keyset's index terms, run again with\n  \
                 AWS_KMS_DEMO_KEY_ID={kms_key_id}\n  \
                 AWS_KMS_DEMO_INDEX_KEY_ID={}",
                hex(key_id.as_bytes())
            );
            key_id
        }
    };

    let registry = StaticKeysetRegistry::new(StaticKeyset::new(
        KEYSET_ID,
        FixedIndexKeySource::new(source, index_key_id),
    ));
    let cipher = StackCipherBuilder::new().registry(registry).init().await?;
    println!("built a StackCipher over AWS KMS");

    let sealed = cipher
        .default_keyset()
        .encrypt("hello from AWS KMS".to_string(), nonempty!("demo/greeting"))
        .await?;
    let opened: String = cipher.decrypt(sealed, nonempty!("demo/greeting")).await?;
    assert_eq!(opened, "hello from AWS KMS");
    println!("round-tripped a value through stack-encrypt and AWS KMS: {opened:?}");

    Ok(())
}

/// An environment variable, or `None` when it is unset or empty.
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The AWS KMS client, or `None` when the demo targets LocalStack and
/// nothing is listening there.
///
/// Only that case is a skip. Any answer from KMS that refuses the call (bad
/// credentials, an IAM policy without `kms:ListKeys`) is an error, and so is
/// an unreachable endpoint the caller chose: either means the demo cannot
/// run as configured, and exiting with success would hide it.
async fn build_client() -> Result<Option<aws_sdk_kms::Client>, Box<dyn Error>> {
    use aws_config::{BehaviorVersion, Region};

    // Unset: LocalStack. Empty: the SDK's own endpoint and credentials.
    let endpoint_url =
        std::env::var("AWS_KMS_DEMO_ENDPOINT_URL").unwrap_or_else(|_| LOCALSTACK.to_string());
    let localstack = endpoint_url == LOCALSTACK;

    let mut loader = aws_config::defaults(BehaviorVersion::v2026_01_12());
    if !endpoint_url.is_empty() {
        // A local endpoint: fixed region, and fake static credentials,
        // which LocalStack accepts.
        let credentials = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "demo");
        loader = loader
            .region(Region::new("us-east-1"))
            .credentials_provider(credentials)
            .endpoint_url(endpoint_url);
    }
    let client = aws_sdk_kms::Client::new(&loader.load().await);

    // A cheap call that fails fast, before the demo creates anything.
    match client.list_keys().limit(1).send().await {
        Ok(_) => Ok(Some(client)),
        Err(SdkError::DispatchFailure(_) | SdkError::TimeoutError(_)) if localstack => Ok(None),
        Err(error) => Err(format!(
            "AWS KMS refused or did not answer ListKeys: {}",
            DisplayErrorContext(&error)
        )
        .into()),
    }
}

async fn create_symmetric_key(client: &aws_sdk_kms::Client) -> Result<String, Box<dyn Error>> {
    use aws_sdk_kms::types::{KeySpec, KeyUsageType};

    // `EncryptDecrypt` usage and a symmetric spec are what GenerateDataKey
    // and Decrypt, the two calls `AwsDataKeySource` makes, require.
    let key = client
        .create_key()
        .key_usage(KeyUsageType::EncryptDecrypt)
        .key_spec(KeySpec::SymmetricDefault)
        .send()
        .await
        .map_err(|error| format!("CreateKey failed: {}", DisplayErrorContext(&error)))?;

    Ok(key
        .key_metadata
        .map(|metadata| metadata.key_id)
        .ok_or("AWS KMS did not return key metadata")?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !hex.len().is_multiple_of(2) {
        return Err("AWS_KMS_DEMO_INDEX_KEY_ID must be hex, two digits a byte".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "AWS_KMS_DEMO_INDEX_KEY_ID must be hex".into())
        })
        .collect()
}
