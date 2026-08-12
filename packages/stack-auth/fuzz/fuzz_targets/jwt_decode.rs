#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the JWT claims decode path on arbitrary UTF-8. stack-auth reads claims
// from tokens it already holds without verifying the signature, so the decoder
// must never panic on a malformed token — only return `Err`.
// `Token::fuzz_decode_claims` is a `fuzz`-feature-gated entry point that runs
// the real decode and discards the claims. Decoding uses the hand-rolled
// base64/JSON path (`decode_jwt_payload`) on every target now, so this exercises
// the same code that runs in production.
fuzz_target!(|s: &str| {
    let _ = stack_auth::Token::fuzz_decode_claims(s);
});
