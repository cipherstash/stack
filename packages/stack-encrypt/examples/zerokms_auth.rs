//! Wiring a cipher to real ZeroKMS, and to a custom authentication strategy.
//!
//! Every example talks to real ZeroKMS. This one shows where the credentials
//! come from, and how to substitute your own when the defaults do not fit.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p stack-encrypt --example zerokms_auth
//! ```
//!
//! Without ZeroKMS credentials in the environment it prints what it *would*
//! do and exits — so it is safe to run anywhere, and CI builds it either way.

use stack_auth::{AuthError, AuthStrategyFn, SecretToken, ServiceToken};
use stack_encrypt::StackCipher;
use stack_kms::{EnvKeyProvider, StackKmsBuilder};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- The default: credentials from the environment ----------------------
    //
    // `StackCipher::new()` is `StackKmsBuilder::auto()` plus the environment's
    // client key, plus a keyset resolution. `auto()` detects whichever
    // strategy the environment is configured for (an access key in CI, a
    // device session on a developer machine).
    //
    // CS_WORKSPACE_CRN + CS_CLIENT_ACCESS_KEY authenticate; CS_CLIENT_ID +
    // CS_CLIENT_KEY are the client key that unwraps data keys.
    let cipher = match StackCipher::new().await {
        Ok(cipher) => cipher,
        // Nothing to connect to: say so and exit cleanly, so the example is
        // safe to run anywhere.
        Err(stack_encrypt::Error::Config(why)) => {
            println!("not configured for ZeroKMS: {why}");
            println!("set CS_CLIENT_ID / CS_CLIENT_KEY and access-key credentials to run this.");
            return Ok(());
        }
        Err(other) => return Err(other.into()),
    };
    println!("connected; keyset {}", cipher.keyset_id());

    let ciphertext = cipher.encrypt("hello".to_string(), "demo/greeting").await?;
    let plaintext: String = cipher.decrypt(ciphertext, "demo/greeting").await?;
    assert_eq!(plaintext, "hello");
    println!("round-tripped a value under the default keyset");

    // --- A specific keyset --------------------------------------------------
    //
    // The keyset pins both halves at once: data keys are generated under it,
    // and its index key derives every SEM term. They cannot diverge.
    //
    //     StackCipher::builder()
    //         .keyset(IdentifiedBy::Name("customers".into()))
    //         .init()
    //         .await?;

    // --- A custom authentication strategy -----------------------------------
    //
    // When the built-in strategies do not fit — tokens from your own broker, a
    // sidecar, a test double — build the `StackKms` yourself and hand it to
    // the builder. Any `AuthStrategy` works; `AuthStrategyFn` wraps a closure.
    //
    // The same seam takes `AccessKeyStrategy`, `DeviceSessionStrategy`, or an
    // OIDC federation strategy when you want to name one explicitly rather
    // than let `auto()` detect it.
    let token = std::env::var("MY_SERVICE_TOKEN").unwrap_or_default();
    let strategy = AuthStrategyFn::new(move || {
        // Your token source: a broker, a sidecar, a cached credential. Called
        // whenever ZeroKMS needs a fresh token, so refresh belongs in here.
        let token = token.clone();
        async move { Ok::<_, AuthError>(ServiceToken::new(SecretToken::new(token))) }
    });

    let kms = StackKmsBuilder::new(strategy)
        .with_key_provider(EnvKeyProvider)
        .build()
        .await?;

    let _cipher = StackCipher::builder().kms(kms).init().await?;
    println!("built a second cipher over a custom auth strategy");

    Ok(())
}
