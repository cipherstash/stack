#![no_main]

use libfuzzer_sys::fuzz_target;
use stack_encrypt::SealedValue;

// Fuzz the frozen v1 leaf byte decoder. A stored ciphertext column comes back
// through `SealedValue::from_bytes` before anything is authenticated, so the
// bytes are attacker-controlled: decoding must never panic, only return `Err`.
//
// The format is documented as lossless, so a second invariant is checked on
// every accepted input: re-encoding gives back exactly the bytes decoded.
// A decoder that accepts bytes it cannot reproduce would let two distinct
// stored forms alias one leaf.
fuzz_target!(|bytes: &[u8]| {
    if let Ok(leaf) = SealedValue::from_bytes(bytes) {
        assert_eq!(leaf.to_bytes(), bytes, "SealedValue decode is not lossless");
    }
});
