//! JSON paths: how a caller names a node of a document.
//!
//! The grammar is `stack-encrypt-jsonpath`'s, which the derive reads too, so
//! a path declared on a field and the same path given at run time are one
//! path. [`JsonPath`], [`Segment`] and [`JsonPathError`] are re-exported from
//! there.
//!
//! What the index derives from a path is this module's: the canonical bytes
//! a selector and a token are derived over, and the document that holds a
//! value at a path. Those are part of the stored format, so they stay with
//! the engine, on [`IndexPath`].
use zeroize::Zeroizing;

pub use stack_encrypt_jsonpath::{JsonPath, JsonPathError, Segment};

/// The tag byte of an object step in a path's canonical bytes.
const KEY_STEP: u8 = 0x01;
/// The tag byte of an array step (positional or wildcard) in a path's
/// canonical bytes.
pub(crate) const ARRAY_STEP: u8 = 0x02;

/// What the JSON index derives from a path. A trait of this crate's, since
/// [`JsonPath`] is the grammar crate's type.
pub(crate) trait IndexPath: Sized {
    /// The path of these steps, from the root down.
    fn of(segments: Vec<Segment>) -> Self;
    /// This path with one more step.
    fn then(&self, segment: Segment) -> Self;
    /// The values at this path in `value`, as [`JsonPath::select`] finds
    /// them, borrowed mutably: so that a caller holding the whole document
    /// can move the nodes it wants out of it rather than copy them.
    fn select_mut<'a>(&self, value: &'a mut serde_json::Value) -> Vec<&'a mut serde_json::Value>;
    /// The canonical bytes a selector is derived over: every array step,
    /// positional or wildcard, is the one array tag, so every element of an
    /// array shares its parent's selector. A key is length-prefixed, so two
    /// paths cannot encode to one byte string.
    fn selector_bytes(&self) -> Zeroizing<Vec<u8>>;
    /// [`selector_bytes`](Self::selector_bytes), moved into a `Protected`.
    fn protected_selector_bytes(&self) -> vitaminc_protected::Protected<Vec<u8>>;
    /// The canonical bytes a token is derived over: an array step carries
    /// its position. `None` for a path with a wildcard, which names no one
    /// node.
    fn token_bytes(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// The document that holds `value` at this path and nothing else:
    /// `$.a[*].x` with `1` is `{"a": [{"x": 1}]}`. A positional array step
    /// places the value at element zero, since the selectors of a query do
    /// not tell positions apart.
    fn holding(&self, value: serde_json::Value) -> serde_json::Value;
}

impl IndexPath for JsonPath {
    fn of(segments: Vec<Segment>) -> Self {
        Self::from(segments)
    }

    fn then(&self, segment: Segment) -> Self {
        let segments = self.segments();
        let mut out = Vec::with_capacity(segments.len() + 1);
        out.extend_from_slice(segments);
        out.push(segment);
        Self::from(out)
    }

    fn select_mut<'a>(&self, value: &'a mut serde_json::Value) -> Vec<&'a mut serde_json::Value> {
        let mut current = vec![value];
        for segment in self.segments() {
            let mut next = Vec::new();
            for node in current {
                match segment {
                    Segment::Key(key) => {
                        next.extend(node.as_object_mut().and_then(|o| o.get_mut(key)));
                    }
                    Segment::Index(index) => next.extend(
                        usize::try_from(*index)
                            .ok()
                            .and_then(|i| node.as_array_mut().and_then(|a| a.get_mut(i))),
                    ),
                    Segment::Wildcard => next.extend(node.as_array_mut().into_iter().flatten()),
                }
            }
            current = next;
        }
        current
    }

    fn selector_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Sized before it is written: a buffer that grew would free a copy
        // of the key names it held.
        let len = self
            .segments()
            .iter()
            .map(|segment| match segment {
                Segment::Key(key) => key_step_len(key.len()),
                Segment::Index(_) | Segment::Wildcard => 1,
            })
            .sum();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        for segment in self.segments() {
            match segment {
                Segment::Key(key) => push_key(&mut out, key),
                Segment::Index(_) | Segment::Wildcard => out.push(ARRAY_STEP),
            }
        }
        out
    }

    fn protected_selector_bytes(&self) -> vitaminc_protected::Protected<Vec<u8>> {
        vitaminc_protected::Protected::new(std::mem::take(&mut *self.selector_bytes()))
    }

    fn token_bytes(&self) -> Option<Zeroizing<Vec<u8>>> {
        let len = self
            .segments()
            .iter()
            .map(|segment| match segment {
                Segment::Key(key) => key_step_len(key.len()),
                Segment::Index(_) | Segment::Wildcard => 1 + 8,
            })
            .sum();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        for segment in self.segments() {
            match segment {
                Segment::Key(key) => push_key(&mut out, key),
                Segment::Index(index) => {
                    out.push(ARRAY_STEP);
                    out.extend_from_slice(&index.to_le_bytes());
                }
                Segment::Wildcard => return None,
            }
        }
        Some(out)
    }

    fn holding(&self, value: serde_json::Value) -> serde_json::Value {
        self.segments()
            .iter()
            .rev()
            .fold(value, |inner, segment| match segment {
                Segment::Key(key) => {
                    let mut map = serde_json::Map::new();
                    let _ = map.insert(key.clone(), inner);
                    serde_json::Value::Object(map)
                }
                Segment::Index(_) | Segment::Wildcard => serde_json::Value::Array(vec![inner]),
            })
    }
}

/// A key step: the tag, the key's length and the key. What
/// [`JsonPath::selector_bytes`] writes for a key, and what a walk's rows
/// are checked against when the client extends a path by a member's
/// decrypted key.
pub(crate) fn push_key(out: &mut Vec<u8>, key: &str) {
    out.push(KEY_STEP);
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
}

/// How many bytes [`push_key`] writes for a key of `len` bytes.
pub(crate) const fn key_step_len(len: usize) -> usize {
    1 + 4 + len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_reports_its_reason_and_offset_and_not_the_text() {
        use crate::ErrorPayload;
        let error = JsonPath::parse("$.secret[x]").unwrap_err();
        let payload = error.payload();
        assert_eq!(
            payload.get("reason"),
            Some(&serde_json::json!(
                "expected `*`, a quoted name or a position after `[`"
            ))
        );
        assert_eq!(payload.get("at"), Some(&serde_json::json!(9)));
        assert_eq!(payload.len(), 2, "{payload:?}");
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn a_selector_folds_positions_into_the_wildcard_and_a_token_keeps_them() {
        let positional = JsonPath::parse("$.a[2].x").unwrap();
        let wild = JsonPath::parse("$.a[*].x").unwrap();
        assert_eq!(positional.selector_bytes(), wild.selector_bytes());
        assert!(positional.token_bytes().is_some());
        assert!(wild.token_bytes().is_none());
        assert_ne!(
            JsonPath::parse("$.a[1]").unwrap().token_bytes(),
            JsonPath::parse("$.a[2]").unwrap().token_bytes()
        );
        // Length-prefixed keys: `("ab", "c")` and `("a", "bc")` differ.
        assert_ne!(
            JsonPath::parse("$.ab.c").unwrap().selector_bytes(),
            JsonPath::parse("$.a.bc").unwrap().selector_bytes()
        );
    }

    /// The byte encodings hold key names, so each is sized before it is
    /// written: a buffer that grew would free a copy. (That they and a path
    /// wipe on drop is held by `tests/heap_hygiene.rs`.)
    #[test]
    fn the_byte_encodings_are_sized_once() {
        use vitaminc_protected::Controlled;
        for text in ["$", "$.a", "$.a[3].bc", r#"$["a b"][*][0]"#, "$[1][2].k"] {
            let path = JsonPath::parse(text).unwrap();
            let selector = path.selector_bytes();
            assert_eq!(selector.len(), selector.capacity(), "{text}: selector");
            if let Some(token) = path.token_bytes() {
                assert_eq!(token.len(), token.capacity(), "{text}: token");
            }
            let protected = path.protected_selector_bytes();
            assert_eq!(protected.risky_ref(), &*selector, "{text}: protected");
        }
    }

    #[test]
    fn the_document_holding_a_value_puts_it_at_the_path() {
        let holding = JsonPath::parse("$.a[*].x")
            .unwrap()
            .holding(serde_json::json!(1));
        assert_eq!(holding, serde_json::json!({"a": [{"x": 1}]}));
        let holding = JsonPath::root().holding(serde_json::json!("v"));
        assert_eq!(holding, serde_json::json!("v"));
    }

    #[test]
    fn select_mut_reaches_what_select_reaches() {
        let doc = serde_json::json!({"a": [{"x": 1}, {"x": 2}, 3], "b": {"x": 4}});
        for text in [
            "$", "$.a", "$.a[1].x", "$.a[*].x", "$.a[*]", "$.b.x", "$.a.x", "$.b[0]", "$.c",
        ] {
            let path = JsonPath::parse(text).unwrap();
            let mut copy = doc.clone();
            let found: Vec<serde_json::Value> = path.select(&doc).into_iter().cloned().collect();
            let found_mut: Vec<serde_json::Value> = path
                .select_mut(&mut copy)
                .into_iter()
                .map(|v| v.clone())
                .collect();
            assert_eq!(found_mut, found, "{text}");
        }
    }
}
