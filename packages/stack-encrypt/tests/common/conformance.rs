//! Typed inputs shared by conformance profiles.
use super::frames::frame;
use serde::Deserialize;
use stack_encrypt::dynamic::ValueFrame;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

pub fn value(input: &Input) -> ValueFrame {
    match input.kind.as_str() {
        "int32" => frame(input.text.parse::<i32>().expect("i32")),
        "int64" => frame(input.text.parse::<i64>().expect("i64")),
        "uint64" => frame(input.text.parse::<u64>().expect("u64")),
        "float64" => frame(input.text.parse::<f64>().expect("f64")),
        "bool" => frame(input.text.parse::<bool>().expect("bool")),
        "string" => frame(input.text.clone()),
        "null" => {
            assert!(input.text.is_empty());
            use vitaminc_aead::plaintext::{Physical, Raw};
            frame(Raw(None, Physical::Null))
        }
        other => panic!("unsupported input kind {other}"),
    }
}
