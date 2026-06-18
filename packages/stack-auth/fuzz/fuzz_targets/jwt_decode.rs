#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the JWT claims decode path on arbitrary UTF-8. stack-auth reads claims
// from tokens it already holds with signature validation disabled
// (`insecure_disable_signature_validation()`), so the decoder must never panic
// on a malformed token — only return `Err`. `Token::fuzz_decode_claims` is a
// `fuzz`-feature-gated entry point that runs the real decode and discards the
// claims. On native this exercises the `jsonwebtoken` path; the hand-rolled
// wasm base64/JSON decoder needs a wasm build (its `base64` dep is wasm-only).
fuzz_target!(|s: &str| {
    let _ = stack_auth::Token::fuzz_decode_claims(s);
});
