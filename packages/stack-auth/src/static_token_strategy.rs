use crate::{AuthError, AuthStrategy, SecretToken, ServiceToken};

/// A simple [`AuthStrategy`] that always returns a fixed token.
///
/// Useful in tests where a token has already been obtained (e.g. from a mock auth
/// server or via federation) and just needs to be presented as-is.
///
/// ```
/// use stack_auth::{StaticTokenStrategy, AuthStrategy};
///
/// # async fn example() {
/// let strategy = StaticTokenStrategy::new("my-token");
/// let token = (&strategy).get_token().await.unwrap();
/// assert_eq!(token.as_str(), "my-token");
/// # }
/// ```
pub struct StaticTokenStrategy(SecretToken);

impl StaticTokenStrategy {
    /// Create a new `StaticTokenStrategy` wrapping the given token string.
    pub fn new(token: impl Into<String>) -> Self {
        Self(SecretToken::new(token))
    }
}

impl AuthStrategy for &StaticTokenStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        Ok(ServiceToken::new(self.0.clone()))
    }
}
