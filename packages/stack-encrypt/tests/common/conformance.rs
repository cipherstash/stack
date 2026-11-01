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

/// Inspect actual stored output, shared by scalar and runtime profiles.
pub fn stored_outputs(
    tree: &stack_encrypt::StackCipherText,
    field: &str,
) -> Option<(Vec<u8>, usize)> {
    use stack_encrypt::CipherText;
    let CipherText::Map(fields) = tree else {
        panic!("expected record")
    };
    assert!(fields.len() <= 1 && fields.iter().all(|(name, _)| name == field));
    let (_, node) = fields.iter().find(|(name, _)| name == field)?;
    let CipherText::Map(outputs) = node else {
        panic!("expected outputs")
    };
    assert_eq!(outputs.len(), 2);
    let CipherText::Single(leaf) = &outputs.iter().find(|(name, _)| name == "c").unwrap().1 else {
        panic!("expected ciphertext")
    };
    let CipherText::Passthrough(term) = &outputs.iter().find(|(name, _)| name == "eq").unwrap().1
    else {
        panic!("expected equality bytes")
    };
    Some((
        vitaminc_aead_frame::serde::from_slice::<&[u8]>(&term.0)
            .unwrap()
            .to_vec(),
        leaf.to_bytes().len(),
    ))
}
pub fn refusal(error: &stack_encrypt::dynamic::Error, code: &str, reason: &str, field: &str) {
    use miette::Diagnostic;
    assert_eq!(error.code().unwrap().to_string(), code);
    assert_eq!(error.reason().unwrap().as_str(), reason);
    assert_eq!(error.field(), Some(field));
}
