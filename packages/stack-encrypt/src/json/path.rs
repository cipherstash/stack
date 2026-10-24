//! JSON paths: how a caller names a node of a document.
//!
//! A [`JsonPath`] is parsed from the JSONPath subset the JSON index
//! addresses: `$`, object members (`.name` or `["name"]`), array elements
//! by position (`[2]`) and every element of an array (`[*]`). Nothing else:
//! no filters, no recursive descent, no slices.
//!
//! The index derives two things from a path, and they differ on arrays:
//!
//! - A **selector** names a path with every array position replaced by the
//!   wildcard, because every element of an array shares one selector
//!   ([`JsonPath::selector_bytes`]). `$.a[2].x` and `$.a[*].x` have the same
//!   selector.
//! - A **token** names a path positionally ([`JsonPath::token_bytes`]), so a
//!   path with a wildcard has none: the token chain addresses one node.
use std::fmt;
use std::str::FromStr;

/// One step of a [`JsonPath`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Segment {
    /// An object member, by key.
    Key(String),
    /// One array element, by position.
    Index(u64),
    /// Every element of an array.
    Wildcard,
}

/// A path into a JSON document, from the root (`$`) down.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct JsonPath {
    segments: Vec<Segment>,
}

/// Why text is not a [`JsonPath`]. The message names the position of the
/// first character the parser refused and nothing else of the text: a path
/// can name a key that is customer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[error("not a JSON path: {reason} at byte {at}")]
#[diagnostic(
    code(stack_encrypt::json_path),
    help("A path starts with `$` and continues with `.name`, `[\"name\"]`, `[2]` or `[*]` steps, as in `$.address.city` or `$.tags[*]`.")
)]
pub struct JsonPathError {
    /// What was expected, or what was found.
    pub reason: &'static str,
    /// The byte offset in the text the parser stopped at.
    pub at: usize,
}

impl crate::ErrorPayload for JsonPathError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        crate::diagnostic::payload([
            ("reason", self.reason.into()),
            ("at", (self.at as u64).into()),
        ])
    }
}

/// The tag byte of an object step in a path's canonical bytes.
const KEY_STEP: u8 = 0x01;
/// The tag byte of an array step (positional or wildcard) in a path's
/// canonical bytes.
pub(crate) const ARRAY_STEP: u8 = 0x02;

impl JsonPath {
    /// The root, `$`.
    pub fn root() -> Self {
        Self::default()
    }

    /// Parse the JSONPath subset the index addresses: `$`, `.name`,
    /// `["name"]`, `[2]` and `[*]` steps.
    ///
    /// # Errors
    ///
    /// [`JsonPathError`] for text that is not one.
    pub fn parse(text: &str) -> Result<Self, JsonPathError> {
        // The parser walks a cursor, `rest`: the text not yet read. Every
        // step strips at least one byte from its front, so the loop ends on
        // any input, and a refusal names the offset of what was left.
        let at = |rest: &str| text.len() - rest.len();
        let refuse = |reason, rest: &str| {
            Err(JsonPathError {
                reason,
                at: at(rest),
            })
        };
        let Some(mut rest) = text.strip_prefix('$') else {
            return refuse("expected `$`", text);
        };
        let mut segments = Vec::new();
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('.') {
                let end = after.find(['.', '[']).unwrap_or(after.len());
                if end == 0 {
                    return refuse("expected a member name after `.`", after);
                }
                // `end` is at an ASCII delimiter or the end of the text, so
                // the split falls on a character boundary.
                let (name, next) = after.split_at(end);
                segments.push(Segment::Key(name.to_owned()));
                rest = next;
            } else if let Some(after) = rest.strip_prefix('[') {
                if let Some(star) = after.strip_prefix('*') {
                    let Some(next) = star.strip_prefix(']') else {
                        return refuse("expected `]` after `*`", star);
                    };
                    segments.push(Segment::Wildcard);
                    rest = next;
                } else if after.starts_with('"') {
                    let (key, next) = match quoted(after) {
                        Ok(parts) => parts,
                        Err(reason) => return refuse(reason, after),
                    };
                    let Some(next) = next.strip_prefix(']') else {
                        return refuse("expected `]` after the quoted name", next);
                    };
                    segments.push(Segment::Key(key));
                    rest = next;
                } else if after.starts_with(|c: char| c.is_ascii_digit()) {
                    let end = after
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(after.len());
                    let (digits, next) = after.split_at(end);
                    let Some(next) = next.strip_prefix(']') else {
                        return refuse("expected `]` after the position", next);
                    };
                    let Ok(index) = digits.parse::<u64>() else {
                        return refuse("the position does not fit 64 bits", after);
                    };
                    segments.push(Segment::Index(index));
                    rest = next;
                } else {
                    return refuse("expected `*`, a quoted name or a position after `[`", after);
                }
            } else {
                return refuse("expected `.` or `[`", rest);
            }
        }
        Ok(Self { segments })
    }

    /// The steps, from the root down. Empty for the root itself.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether some step is an array position (`[2]`), which a selector
    /// reads as the wildcard.
    pub(crate) fn names_a_position(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Segment::Index(_)))
    }

    /// Whether this path names one node: no step is the wildcard.
    pub fn is_positional(&self) -> bool {
        !self.segments.iter().any(|s| matches!(s, Segment::Wildcard))
    }

    /// Whether this path, read as a pattern, covers `path`: the same
    /// steps, except that a wildcard here covers any array step there, a
    /// position or the wildcard. A position here covers that position
    /// alone, not the wildcard, since the wildcard names elements the
    /// position does not. How the index's ordered paths
    /// ([`JsonOptions::ordered`](super::JsonOptions::ordered)) are matched
    /// against a node's path when a document is sealed, and against a
    /// query's path when an ordering is asked.
    ///
    /// ```
    /// use stack_encrypt::json::JsonPath;
    ///
    /// let wild = JsonPath::parse("$.orders[*].total").unwrap();
    /// assert!(wild.covers(&JsonPath::parse("$.orders[3].total").unwrap()));
    /// assert!(wild.covers(&JsonPath::parse("$.orders[*].total").unwrap()));
    /// let third = JsonPath::parse("$.orders[3].total").unwrap();
    /// assert!(third.covers(&JsonPath::parse("$.orders[3].total").unwrap()));
    /// assert!(!third.covers(&JsonPath::parse("$.orders[2].total").unwrap()));
    /// assert!(!third.covers(&JsonPath::parse("$.orders[*].total").unwrap()));
    /// assert!(!wild.covers(&JsonPath::parse("$.orders[*]").unwrap()));
    /// ```
    pub fn covers(&self, path: &JsonPath) -> bool {
        self.segments.len() == path.segments.len()
            && self
                .segments
                .iter()
                .zip(&path.segments)
                .all(|(pattern, step)| match (pattern, step) {
                    (Segment::Key(a), Segment::Key(b)) => a == b,
                    (Segment::Wildcard, Segment::Index(_) | Segment::Wildcard) => true,
                    (Segment::Index(a), Segment::Index(b)) => a == b,
                    _ => false,
                })
    }

    /// The values at this path in `value`, in document order: at most one
    /// for a positional path, one per element a wildcard reaches, none when
    /// the path names nothing. A key step into an array, or a position
    /// into an object, reaches nothing, as the token chain reaches nothing
    /// there. What a client takes over a whole document when a walk
    /// returned the sealed root in place of the subtree.
    pub fn select<'a>(&self, value: &'a serde_json::Value) -> Vec<&'a serde_json::Value> {
        let mut current = vec![value];
        for segment in &self.segments {
            let mut next = Vec::new();
            for node in current {
                match segment {
                    Segment::Key(key) => next.extend(node.as_object().and_then(|o| o.get(key))),
                    Segment::Index(index) => next.extend(
                        usize::try_from(*index)
                            .ok()
                            .and_then(|i| node.as_array().and_then(|a| a.get(i))),
                    ),
                    Segment::Wildcard => next.extend(node.as_array().into_iter().flatten()),
                }
            }
            current = next;
        }
        current
    }

    /// The values at this path in `value`, as [`select`](Self::select)
    /// finds them, borrowed mutably: so that a caller holding the whole
    /// document can move the nodes it wants out of it rather than copy
    /// them.
    pub(crate) fn select_mut<'a>(
        &self,
        value: &'a mut serde_json::Value,
    ) -> Vec<&'a mut serde_json::Value> {
        let mut current = vec![value];
        for segment in &self.segments {
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

    /// This path with one more step.
    pub(crate) fn then(&self, segment: Segment) -> Self {
        let mut segments = Vec::with_capacity(self.segments.len() + 1);
        segments.extend_from_slice(&self.segments);
        segments.push(segment);
        Self { segments }
    }

    /// The canonical bytes a selector is derived over: every array step,
    /// positional or wildcard, is the one array tag, so every element of an
    /// array shares its parent's selector. A key is length-prefixed, so two
    /// paths cannot encode to one byte string.
    pub(crate) fn selector_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for segment in &self.segments {
            match segment {
                Segment::Key(key) => push_key(&mut out, key),
                Segment::Index(_) | Segment::Wildcard => out.push(ARRAY_STEP),
            }
        }
        out
    }

    /// The canonical bytes a token is derived over: an array step carries
    /// its position. `None` for a path with a wildcard, which names no one
    /// node.
    pub(crate) fn token_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for segment in &self.segments {
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

    /// The document that holds `value` at this path and nothing else:
    /// `$.a[*].x` with `1` is `{"a": [{"x": 1}]}`. A positional array step
    /// places the value at element zero, since the needle's selectors do not
    /// tell positions apart.
    pub(crate) fn needle(&self, value: serde_json::Value) -> serde_json::Value {
        self.segments
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

/// The JSON string at the front of `text`, which starts at its opening
/// quote: its value and the text after its closing quote. The escapes are
/// JSON's. The refusal is the reason; the caller names the offset.
fn quoted(text: &str) -> Result<(String, &str), &'static str> {
    let mut escaped = false;
    for (end, byte) in text.bytes().enumerate().skip(1) {
        match (escaped, byte) {
            (true, _) => escaped = false,
            (false, b'\\') => escaped = true,
            (false, b'"') => {
                let key: String = serde_json::from_str(&text[..=end])
                    .map_err(|_| "the quoted name is not a JSON string")?;
                return Ok((key, &text[end + 1..]));
            }
            (false, _) => {}
        }
    }
    Err("unterminated quoted name")
}

impl FromStr for JsonPath {
    type Err = JsonPathError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Renders the path as it parses: a plain key as `.key`, any other as
/// `["…"]`, a position as `[2]`, the wildcard as `[*]`.
impl fmt::Display for JsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("$")?;
        for segment in &self.segments {
            match segment {
                Segment::Key(key) if !key.is_empty() && !key.contains(['.', '[', ']', '"']) => {
                    write!(f, ".{key}")?;
                }
                Segment::Key(key) => {
                    write!(f, "[{}]", serde_json::Value::String(key.clone()))?;
                }
                Segment::Index(index) => write!(f, "[{index}]")?,
                Segment::Wildcard => f.write_str("[*]")?,
            }
        }
        Ok(())
    }
}

/// A path serializes as its text, as [`Display`](fmt::Display) renders it,
/// so a plan's ordered paths read as `["$.age"]` on the wire.
impl serde::Serialize for JsonPath {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// A path deserializes from its text through [`JsonPath::parse`], so a
/// string that is not a path is refused where it is read, with the
/// [`JsonPathError`]'s message.
impl<'de> serde::Deserialize<'de> for JsonPath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &str) -> Segment {
        Segment::Key(k.to_owned())
    }

    #[test]
    fn parses_the_subset_the_index_addresses() {
        let path = JsonPath::parse("$.a[2].b[*][\"c.d\"]").unwrap();
        assert_eq!(
            path.segments(),
            &[
                key("a"),
                Segment::Index(2),
                key("b"),
                Segment::Wildcard,
                key("c.d")
            ]
        );
        assert_eq!(path.to_string(), "$.a[2].b[*][\"c.d\"]");
        assert_eq!(JsonPath::parse("$").unwrap(), JsonPath::root());
        assert_eq!(JsonPath::parse("$").unwrap().to_string(), "$");
        assert!(!path.is_positional());
        assert!(JsonPath::parse("$.a[2]").unwrap().is_positional());
    }

    #[test]
    fn selects_what_the_chain_would_reach() {
        let doc = serde_json::json!({
            "a": [{"x": 1}, {"x": 2, "y": [3, 4]}, 5],
            "b": {"c": "d"},
        });
        let at = |text: &str| JsonPath::parse(text).unwrap().select(&doc);
        assert_eq!(at("$"), vec![&doc]);
        assert_eq!(at("$.b.c"), vec![&serde_json::json!("d")]);
        assert_eq!(at("$.a[1].x"), vec![&serde_json::json!(2)]);
        assert_eq!(
            at("$.a[*].x"),
            vec![&serde_json::json!(1), &serde_json::json!(2)]
        );
        assert_eq!(
            at("$.a[*].y[*]"),
            vec![&serde_json::json!(3), &serde_json::json!(4)]
        );
        assert!(at("$.a.x").is_empty(), "a key step into an array");
        assert!(at("$.b[0]").is_empty(), "a position into an object");
        assert!(at("$.a[3]").is_empty(), "past the end");
        assert!(at("$.b[*]").is_empty(), "the wildcard over an object");
        assert!(at("$.z").is_empty());
        assert!(JsonPath::parse("$[18446744073709551615]")
            .unwrap()
            .select(&doc)
            .is_empty());
    }

    #[test]
    fn refuses_what_it_does_not_address() {
        for (text, at) in [
            ("", 0),
            ("a.b", 0),
            ("$.", 2),
            ("$..a", 2),
            ("$[", 2),
            ("$[1", 3),
            ("$[-1]", 2),
            ("$[\"a]", 2),
            ("$.a[x]", 4),
            ("$[*x", 3),
            ("$[*", 3),
            ("$[\"a\"x", 5),
            ("$[\"a\"", 5),
            ("$[\"\\q\"]", 2),
            ("$[18446744073709551616]", 2),
        ] {
            let error = JsonPath::parse(text).unwrap_err();
            assert_eq!(error.at, at, "{text:?}: {error}");
        }
        // A plain key runs to the next `.` or `[`, so it may hold a space.
        assert_eq!(JsonPath::parse("$.a b").unwrap().segments(), &[key("a b")]);
    }

    #[test]
    fn a_quoted_name_takes_json_escapes() {
        assert_eq!(
            JsonPath::parse(r#"$["a\"b"]"#).unwrap().segments(),
            &[key("a\"b")],
            "an escaped quote does not end the name"
        );
        assert_eq!(
            JsonPath::parse(r#"$["a\\"].b"#).unwrap().segments(),
            &[key("a\\"), key("b")],
            "an escaped backslash does not escape the closing quote"
        );
        assert_eq!(
            JsonPath::parse(r#"$["\u0041"][0]"#).unwrap().segments(),
            &[key("A"), Segment::Index(0)]
        );
        assert_eq!(
            JsonPath::parse("$[18446744073709551615]")
                .unwrap()
                .segments(),
            &[Segment::Index(u64::MAX)]
        );
    }

    #[test]
    fn a_path_parses_through_from_str() {
        let path: JsonPath = "$.a[*]".parse().unwrap();
        assert_eq!(path, JsonPath::parse("$.a[*]").unwrap());
        assert_eq!("$.".parse::<JsonPath>().unwrap_err().at, 2);
    }

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

    /// `covers` is public and matches positions though an ordered path may
    /// not name one: a position covers that position alone.
    #[test]
    fn a_position_covers_its_own_position_only() {
        let path = |text: &str| JsonPath::parse(text).unwrap();
        let third = path("$.orders[3].total");
        assert!(third.covers(&path("$.orders[3].total")));
        assert!(!third.covers(&path("$.orders[2].total")));
        assert!(!third.covers(&path("$.orders[*].total")));
        assert!(path("$.orders[*].total").covers(&third));
        assert!(!path("$.orders[3]").covers(&third), "the same steps only");
    }

    #[test]
    fn a_needle_holds_the_value_at_the_path() {
        let needle = JsonPath::parse("$.a[*].x")
            .unwrap()
            .needle(serde_json::json!(1));
        assert_eq!(needle, serde_json::json!({"a": [{"x": 1}]}));
        let needle = JsonPath::root().needle(serde_json::json!("v"));
        assert_eq!(needle, serde_json::json!("v"));
    }

    #[test]
    fn a_path_round_trips_through_serde_as_its_text() {
        for text in ["$", "$.a[*].b", r#"$["a.b"][2]"#, r#"$["say \"hi\""]"#] {
            let path = JsonPath::parse(text).unwrap();
            let wire = serde_json::to_value(&path).unwrap();
            assert_eq!(wire, serde_json::Value::String(path.to_string()));
            assert_eq!(serde_json::from_value::<JsonPath>(wire).unwrap(), path);
        }
        let refused = serde_json::from_value::<JsonPath>(serde_json::json!("a.b")).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "not a JSON path: expected `$` at byte 0"
        );
        assert!(serde_json::from_value::<JsonPath>(serde_json::json!(1)).is_err());
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
