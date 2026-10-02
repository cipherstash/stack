#![no_main]

use libfuzzer_sys::fuzz_target;
use stack_kms::ClientKey;
use uuid::Uuid;

// Fuzz the public `ClientKey::from_encoded_v1` decoder: hex (either case) or
// standard padded base64, then CBOR keyset decoding. This is the entry point
// front-ends use for key material arriving from an untyped boundary — an
// environment variable, `secretkey.json`, the WASI guest's FFI config object —
// so parsing must never panic: malformed input must return `Err`, not crash.
//
// The key id is fixed: it is not parsed, only stored, so varying it would just
// dilute the corpus. libfuzzer-sys supplies `&str` via the `arbitrary` crate.
fuzz_target!(|s: &str| {
    let _ = ClientKey::from_encoded_v1(Uuid::nil(), s);
});
