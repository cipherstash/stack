//! Fetches a token from the real CTS and verifies it before using it.
//!
//! `verify_tokens` checks each token against the signing keys CTS publishes
//! at `<issuer>/.well-known/jwks.json`, where the issuer is the CTS that
//! serves the workspace's region. This is the live check that CTS's tokens
//! and keys are what the verifier expects (RS256, that issuer, a key it
//! publishes), and CI runs it in `tests-golang.yml`'s `live` job.
//!
//! ```sh
//! CS_CLIENT_ACCESS_KEY=<key> CS_WORKSPACE_CRN=<crn> cargo run --example verify_tokens
//! ```
//!
//! It exits non-zero if the token does not verify.

use stack_auth::{AuthStrategy, AutoStrategy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let strategy = AutoStrategy::builder().verify_tokens().detect()?;
    let token = strategy.get_token().await?;

    #[allow(clippy::print_stdout)]
    {
        println!(
            "Verified a CTS token for workspace {} issued by {}",
            token.workspace_id()?,
            token.issuer()?
        );
    }
    Ok(())
}
