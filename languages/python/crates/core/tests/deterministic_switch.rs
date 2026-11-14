//! The switch to the deterministic client of the `deterministic-kms` test
//! build. A test binary is its own process, and the switch is for the whole
//! process, so these checks run in this binary alone. `test:cargo` runs it
//! with the feature on.

#![cfg(feature = "deterministic-kms")]

use stackencrypt_core::client;

#[test]
fn after_the_switch_the_live_client_is_refused_and_a_second_switch_too() {
    client::use_deterministic([7; 32]).expect("the first switch succeeds");
    assert!(client::deterministic().is_some());

    // An operation that skipped the check for the deterministic client
    // would send requests to ZeroKMS. It is refused instead.
    let Err(refused) = client::shared() else {
        panic!("the live client is refused");
    };
    assert_eq!(refused.code, "stack_test_build");
    assert_eq!(client::build_count(), 0);

    let refused = client::use_deterministic([7; 32]).expect_err("a second switch is refused");
    assert_eq!(refused.code, "stack_test_build");
}
