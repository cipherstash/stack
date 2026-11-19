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
//! On a developer machine, `npx stash auth login` is sufficient. Without any
//! credentials it prints what it *would* do and exits — so it is safe to run
//! anywhere, and CI builds it either way.

use stack_auth::{AuthError, AuthStrategyFn, SecretToken, ServiceToken};
use stack_encrypt::kms::EnvKeyProvider;
use stack_encrypt::StackCipher;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Detected credentials: from the environment or the CLI's login -------
    //
    // `StackCipher::with_detected_credentials()` is the one constructor that
    // looks for credentials itself. Both credentials are looked up the same
    // way: the environment first, then the CLI's profile directory
    // (`~/.cipherstash`, written by `npx stash auth login`):
    //
    //   access token:  CS_CLIENT_ACCESS_KEY + CS_WORKSPACE_CRN, else auth.json
    //   client key:    CS_CLIENT_ID + CS_CLIENT_KEY,            else secretkey.json
    //
    // So a logged-in developer machine needs nothing else; CI sets the four
    // variables.
    let cipher = match StackCipher::with_detected_credentials().await {
        Ok(cipher) => cipher,
        // Nothing to connect to: say so and exit cleanly, so the example is
        // safe to run anywhere.
        Err(stack_encrypt::Error::Config(why)) => {
            println!("not configured for ZeroKMS: {why}");
            println!(
                "run `npx stash auth login`, or set CS_CLIENT_ACCESS_KEY / CS_WORKSPACE_CRN \
                 and CS_CLIENT_ID / CS_CLIENT_KEY, to run this."
            );
            return Ok(());
        }
        // Configured but not accepted — typically a stale device session in
        // ~/.cipherstash or an access key for another workspace. `auto()` only
        // checks that a strategy *exists*; ZeroKMS is the first to say no.
        Err(stack_encrypt::Error::Kms(why)) => {
            println!("could not reach or authenticate with ZeroKMS: {why}");
            println!("check the credentials `auto()` detected (CS_* variables, ~/.cipherstash).");
            return Ok(());
        }
        Err(other) => return Err(other.into()),
    };
    let keyset = cipher.default_keyset();
    println!("connected; keyset {}", keyset.keyset_id());

    let ciphertext = keyset.encrypt_tree("hello", "demo/greeting").await?;
    let plaintext: String = cipher.decrypt(ciphertext, "demo/greeting").await?;
    assert_eq!(plaintext, "hello");
    println!("round-tripped a value under the default keyset");

    // --- A specific keyset --------------------------------------------------
    //
    // A cipher is client-scoped and serves any keyset the client is
    // authorised for; selecting one (loaded from ZeroKMS on first use, then
    // cached) yields a handle that pins both halves at once: data keys are
    // generated under it, and its index key derives every SEM term. They
    // cannot diverge.
    //
    //     let customers = cipher
    //         .keyset(IdentifiedBy::Name("customers".to_string().into()))
    //         .await?;
    //     let ciphertext = customers.encrypt_tree("hello", "demo/greeting").await?;
    //
    // `default_keyset()` above is not one of these: it is the client's own
    // default, the keyset a ZeroKMS administrator set for this client, and
    // selecting others never moves it.

    // --- A custom authentication strategy -----------------------------------
    //
    // Use `auth_strategy` when the detected credentials do not fit. For
    // example, your tokens come from your own broker or from a sidecar. Any
    // `AuthStrategy` works: `AccessKeyStrategy`, `OidcFederationStrategy`,
    // `DeviceSessionStrategy`, or `AuthStrategyFn`. This example uses
    // `AuthStrategyFn`, with a closure.
    //
    // The strategy does not choose the client key. Name the source of the
    // client key with `key_provider`. `EnvKeyProvider` reads `CS_CLIENT_ID`
    // and `CS_CLIENT_KEY`.
    //
    // This section needs a real token. `init` loads the index key of the
    // default keyset, and ZeroKMS must accept the token on that request.
    //
    // Note what the token is held in: `SecretToken` wraps it the moment it is
    // read, and that wrapper — not a bare `String` — is what the closure
    // captures and clones. `SecretToken` is zeroized on drop and prints as
    // `***`, so a long-lived credential neither lingers in freed memory nor
    // lands in a log line.
    let Ok(token) = std::env::var("MY_SERVICE_TOKEN").map(SecretToken::new) else {
        println!("MY_SERVICE_TOKEN not set; skipping the custom-strategy section.");
        return Ok(());
    };
    let strategy = AuthStrategyFn::new(move || {
        // Your token source: a broker, a sidecar, a cached credential. Called
        // whenever ZeroKMS needs a fresh token, so refresh belongs in here.
        let token = token.clone();
        async move { Ok::<_, AuthError>(ServiceToken::new(token)) }
    });

    let _cipher = StackCipher::builder()
        .auth_strategy(strategy)
        .key_provider(EnvKeyProvider)
        .init()
        .await?;
    println!("built a second cipher over a custom auth strategy");

    Ok(())
}
