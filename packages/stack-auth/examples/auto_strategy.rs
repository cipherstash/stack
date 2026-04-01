//! Demonstrates automatic credential detection with [`AutoStrategy`].
//!
//! `AutoStrategy` picks the best available authentication method without
//! requiring the caller to choose one explicitly. It checks for credentials
//! in the following order:
//!
//! 1. **Access key** – if `CS_CLIENT_ACCESS_KEY` is set along with
//!    `CS_WORKSPACE_CRN`, an [`AccessKeyStrategy`] is used.
//! 2. **OAuth** – if a token store file exists at `~/.cipherstash/auth.json`
//!    (written by `stash login`), an [`OAuthStrategy`] is used.
//! 3. If neither is available, an error is returned.
//!
//! # Running the example
//!
//! With an access key:
//!
//! ```sh
//! CS_CLIENT_ACCESS_KEY=<key> CS_WORKSPACE_CRN=<crn> cargo run --example auto_strategy
//! ```
//!
//! Or after authenticating via the CLI:
//!
//! ```sh
//! stash login
//! cargo run --example auto_strategy
//! ```

use stack_auth::{AuthStrategy, AutoStrategy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // AutoStrategy detects credentials automatically:
    //
    //   1. CS_CLIENT_ACCESS_KEY env var  → AccessKeyStrategy
    //   2. ~/.cipherstash/auth.json file → OAuthStrategy
    //   3. Neither                       → error
    let strategy = AutoStrategy::detect()?;

    match &strategy {
        AutoStrategy::AccessKey(_) => println!("Using access key authentication"),
        AutoStrategy::OAuth(_) => println!("Using OAuth authentication"),
    }

    // Obtain a token — refresh happens automatically when needed.
    let token = (&strategy).get_token().await?;
    println!("Subject:      {}", token.subject()?);
    println!("Workspace:    {}", token.workspace_id()?);
    println!("Issuer:       {}", token.issuer()?);

    Ok(())
}
