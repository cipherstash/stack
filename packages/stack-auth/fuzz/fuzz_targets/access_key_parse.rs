#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the public `AccessKey` string parser (`CSAK<key_id>.<key_secret>`).
// libfuzzer-sys supplies `&str` via the `arbitrary` crate. Access keys are
// untrusted credential strings supplied by callers, so parsing them must never
// panic — malformed input must return `Err(InvalidAccessKey)`, not crash.
fuzz_target!(|s: &str| {
    let _ = s.parse::<stack_auth::AccessKey>();
});
