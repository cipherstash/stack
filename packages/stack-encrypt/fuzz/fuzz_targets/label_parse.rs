#![no_main]

use libfuzzer_sys::fuzz_target;
use stack_encrypt::{Descriptor, Label, LabelError};

// Fuzz the label parser (`Label::parse`) and constructor (`Label::new`).
// The text is often the caller's: a binding's record keys and options, a
// data plan's names, and a context field's value, which is customer data.
// So neither may panic, and a label must read back exactly as it renders:
//
// - `parse` accepts text only if the label renders back to that text, and
//   its descriptor is that text too, so two labels never render alike;
// - `new` over segments accepts only if each segment is a one-segment
//   label, and the label it builds has those segments;
// - a refusal names a segment that exists and is refused for the reason
//   the error gives, and every segment before it is accepted alone.
//
// The input is read as UTF-8, lossily. `parse` takes it whole. `new` takes
// it split on the unit separator (0x1F), a control character that no label
// segment holds, so a segment can contain `/` and other reserved text.
fuzz_target!(|bytes: &[u8]| {
    let text = String::from_utf8_lossy(bytes);

    match Label::parse(&text) {
        Ok(label) => {
            assert_eq!(label.to_string(), text, "a label renders as the text it was read from");
            assert_eq!(Descriptor::of(&label).as_str(), text, "a label's descriptor is its text");
            let segments: Vec<&str> = label.segments().collect();
            assert_eq!(segments, text.split('/').collect::<Vec<_>>());
            assert_eq!(Label::new(&segments).ok(), Some(label.clone()));
        }
        Err(error) => check_refusal(&text.split('/').collect::<Vec<_>>(), error),
    }

    let segments: Vec<&str> = text.split('\u{1F}').collect();
    match Label::new(&segments) {
        Ok(label) => {
            assert_eq!(label.segments().collect::<Vec<_>>(), segments);
            for segment in &segments {
                assert!(Label::new([segment]).is_ok(), "each segment is a label alone");
            }
            let rendered = label.to_string();
            assert_eq!(rendered, segments.join("/"));
            assert_eq!(Descriptor::of(&label).as_str(), rendered);
            assert_eq!(Label::parse(&rendered).ok(), Some(label), "a label reads back as it renders");
        }
        Err(error) => check_refusal(&segments, error),
    }
});

/// A refusal of `segments` names a segment that exists, for a reason that
/// segment shows, and every segment before it is accepted alone.
fn check_refusal(segments: &[&str], error: LabelError) {
    let index = match error {
        LabelError::Empty => {
            assert!(segments.is_empty(), "only no segments at all is Empty");
            return;
        }
        LabelError::EmptySegment { index } => {
            assert!(segments[index].is_empty());
            index
        }
        LabelError::Separator { index } => {
            assert!(segments[index].contains('/'));
            index
        }
        LabelError::Reserved { index, found } => {
            assert!(segments[index].contains(found));
            assert!(
                found.is_control() || matches!(found, '(' | ')') || !found.is_ascii(),
                "a reserved character is a control character, a parenthesis or an invisible format character"
            );
            index
        }
        LabelError::ReservedPrefix { index } => {
            let segment = segments[index];
            assert!(
                segment.starts_with("b64:")
                    || segment.starts_with(|c: char| c.is_ascii_digit() || c == '-'),
            );
            index
        }
        other => panic!("a label read from text refused as {other:?}"),
    };
    for segment in &segments[..index] {
        assert!(Label::new([segment]).is_ok(), "a segment before the refused one is accepted");
    }
}
