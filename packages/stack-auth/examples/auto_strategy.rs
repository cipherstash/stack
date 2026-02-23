use stack_auth::{AuthStrategy, AutoStrategy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // AutoStrategy detects credentials automatically:
    //
    //   1. CS_CLIENT_ACCESS_KEY env var  → AccessKeyStrategy
    //   2. ~/.cipherstash/auth.json file → OAuthStrategy
    //   3. Neither                       → error
    let strategy = AutoStrategy::new()?;

    match &strategy {
        AutoStrategy::AccessKey(_) => println!("Using access key authentication"),
        AutoStrategy::OAuth(_) => println!("Using OAuth authentication"),
    }

    // Obtain a token — refresh happens automatically when needed.
    let token = (&strategy).get_token().await?;
    println!("Token type: Bearer");
    println!("Access token: {:?}", token);

    Ok(())
}
