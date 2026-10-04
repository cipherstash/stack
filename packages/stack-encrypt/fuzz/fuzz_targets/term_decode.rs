#![no_main]

use libfuzzer_sys::fuzz_target;
use stack_encrypt::sem::{DefaultMatch, EqualityTerm, MatchTerms, OpeTerm, OreTerm};

// Fuzz the SEM index-term byte decoders: stored terms come back through these
// before comparison, so the bytes are attacker-controlled and decoding must
// never panic. Every kind is run over the same slice; each is a length or
// range check and a crash names its kind in the panic message.
//
// The unframed kinds (equality, ORE, OPE) store the bytes as given, so an
// accepted input must re-encode to itself. A match term normalises its
// positions (sorted, de-duplicated), so only its decode is exercised.
fuzz_target!(|bytes: &[u8]| {
    if let Ok(term) = EqualityTerm::try_from(bytes) {
        assert_eq!(
            term.as_bytes(),
            bytes,
            "EqualityTerm decode is not lossless"
        );
    }
    let _ = MatchTerms::<DefaultMatch>::from_bytes(bytes);
    // One fixed-width and one variable-width CLLW output each for ORE and OPE.
    if let Ok(term) = OreTerm::<u64>::from_bytes(bytes) {
        assert_eq!(
            term.as_bytes(),
            bytes,
            "OreTerm<u64> decode is not lossless"
        );
    }
    if let Ok(term) = OreTerm::<String>::from_bytes(bytes) {
        assert_eq!(
            term.as_bytes(),
            bytes,
            "OreTerm<String> decode is not lossless"
        );
    }
    if let Ok(term) = OpeTerm::<String>::from_bytes(bytes) {
        assert_eq!(
            term.as_bytes(),
            bytes,
            "OpeTerm<String> decode is not lossless"
        );
    }
});
