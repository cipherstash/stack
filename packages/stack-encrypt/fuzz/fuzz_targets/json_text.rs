#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use stack_encrypt::json::{parse_text, to_text, JsonTextError};

// Fuzz the boundary parser a language SDK's JSON document goes through
// (`json::parse_text`): the text is the caller's, so it must never panic.
// It is the engine's own parser, so it is held to serde_json's, which it
// must agree with:
//
// - whatever it reads, serde_json reads to the same value;
// - whatever serde_json reads and it refuses is a repeated member or an
//   integer literal out of the 64-bit range, never a syntax error;
// - what it reads writes back (`to_text`) to text it reads to the same
//   value.
fuzz_target!(|bytes: &[u8]| {
    let ours = parse_text(bytes);
    let theirs = serde_json::from_slice::<Value>(bytes);
    match (&ours, &theirs) {
        (Ok(ours), Ok(theirs)) => assert_eq!(ours, theirs, "the two parsers read different values"),
        (Ok(_), Err(_)) => panic!("parse_text read text serde_json refuses"),
        (Err(JsonTextError::Syntax { .. }), Ok(_)) => {
            panic!("parse_text refused as not JSON text serde_json reads")
        }
        _ => {}
    }
    if let Ok(value) = ours {
        let text = to_text(&value).expect("a value writes");
        assert_eq!(parse_text(&text).ok(), Some(value), "a value does not read back");
    }
});
