use cts_common::Region;
use stack_auth::DeviceCodeStrategy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let region = Region::aws("ap-southeast-2")?;
    let strategy = DeviceCodeStrategy::builder(region, "cli")
        .base_url("http://localhost:3001".parse()?)
        .build()?;

    // Step 1: Begin the device code flow
    let pending = strategy.begin().await?;

    // Step 2: Display the code and open the browser (caller controls this)
    println!("Your code is: {}", pending.user_code());
    println!("Visit: {}", pending.verification_uri_complete());

    if !pending.open_in_browser() {
        eprintln!("Could not open browser — please visit the URL above manually.");
    }

    // Step 3: Poll until the user authorizes
    let token = pending.poll_for_token().await?;

    println!("Token type: {}", token.token_type());
    println!("Expires in: {}s", token.expires_in());
    println!("Access token: {:?}", token.access_token());

    Ok(())
}
