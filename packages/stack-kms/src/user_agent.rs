use lazy_static::lazy_static;
use std::env::consts::{ARCH, OS};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SECONDARY_AGENT: Option<&str> = option_env!("CIPHERSTASH_CLIENT_SECONDARY_USER_AGENT");

pub(crate) fn get_user_agent() -> &'static str {
    lazy_static! {
        static ref USER_AGENT: String = format!(
            "stack-kms/{VERSION} ({OS} {ARCH}{})",
            SECONDARY_AGENT.map(|x| format!(" {x}")).unwrap_or_default()
        );
    }

    &USER_AGENT
}
