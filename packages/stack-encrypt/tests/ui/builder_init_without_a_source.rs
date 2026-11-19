//! A cipher reads credentials only from where the caller's code says. The
//! bare builder has no `init`: name a data-key source first, with `kms(..)`
//! or with `auth_strategy(..)` and `key_provider(..)`. The constructor that
//! detects credentials is named for it:
//! `StackCipher::with_detected_credentials()`.

use stack_encrypt::StackCipher;

async fn bare_builder() {
    let _ = StackCipher::builder().init().await;
}

fn main() {}
