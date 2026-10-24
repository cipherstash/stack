#![no_main]

use libfuzzer_sys::fuzz_target;
use stack_encrypt::json::{JsonDocument, JsonHeader, JsonLeafQuery, JsonNode, JsonProjection};

// Fuzz the JSON index's wire decoders. A stored `json_tree` document, and
// every entry `->` or a walk returns, come back from the database through
// these before anything is authenticated, so the text is attacker-controlled:
// the base64 of the selectors, parent tags, ordering terms and header, the
// base85 of the ciphertexts (decoded with SIMD code on aarch64 and x86_64),
// and the header's frozen byte layout. Decoding must never panic, only
// return `Err`.
//
// An accepted value must also survive a round trip through its own wire
// form unchanged: a decoder that accepts text its encoder cannot reproduce
// would let two stored forms alias one document.
fuzz_target!(|bytes: &[u8]| {
    let _ = JsonHeader::from_bytes(bytes);
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(doc) = serde_json::from_str::<JsonDocument>(text) {
        let wire = serde_json::to_value(&doc).expect("a document serializes");
        let back: JsonDocument = serde_json::from_value(wire).expect("its wire form reads back");
        assert_eq!(back, doc, "JsonDocument wire form is not lossless");
    }
    if let Ok(node) = serde_json::from_str::<JsonNode>(text) {
        let wire = serde_json::to_value(&node).expect("a node serializes");
        let back: JsonNode = serde_json::from_value(wire).expect("its wire form reads back");
        assert_eq!(back, node, "JsonNode wire form is not lossless");
    }
    let _ = serde_json::from_str::<JsonProjection>(text);
    let _ = serde_json::from_str::<JsonLeafQuery>(text);
});
