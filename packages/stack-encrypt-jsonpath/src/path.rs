//! JSON paths: how a caller names a node of a document.
//!
//! A [`JsonPath`] is parsed from the JSONPath subset the JSON index
//! addresses: `$`, object members (`.name` or `["name"]`), array elements
//! by position (`[2]`) and every element of an array (`[*]`). Nothing else:
//! no filters, no recursive descent, no slices.
//!
//! `stack-encrypt`'s JSON index derives two things from a path, and they
//! differ on arrays:
//!
//! - A **selector** names a path with every array position replaced by the
//!   wildcard, because every element of an array shares one selector.
//!   `$.a[2].x` and `$.a[*].x` have the same selector.
//! - A **token** names a path positionally, so a path with a wildcard has
//!   none: the token chain addresses one node.
use std::fmt;
use std::str::FromStr;

use zeroize::{Zeroize, Zeroizing};

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
///
/// A key step's name can be customer data (the walk builds a path for every
/// node of a document it seals or queries), so a path wipes its key names
/// when it drops.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct JsonPath {
    segments: Vec<Segment>,
}

impl Drop for JsonPath {
    fn drop(&mut self) {
        for segment in &mut self.segments {
            if let Segment::Key(key) = segment {
                key.zeroize();
            }
        }
    }
}

/// Why text is not a [`JsonPath`]. The message names the position of the
/// first character the parser refused and nothing else of the text: a path
/// can name a key that is customer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "diagnostics", derive(miette::Diagnostic))]
#[error("not a JSON path: {reason} at byte {at}")]
#[cfg_attr(
    feature = "diagnostics",
    diagnostic(
        code(stack_encrypt::json_path),
        help("A path starts with `$` and continues with `.name`, `[\"name\"]`, `[2]` or `[*]` steps, as in `$.address.city` or `$.tags[*]`.")
    )
)]
pub struct JsonPathError {
    /// What was expected, or what was found.
    pub reason: &'static str,
    /// The byte offset in the text the parser stopped at.
    pub at: usize,
}

/// The reason and the offset, as fields. Never the text.
#[cfg(feature = "diagnostics")]
impl stack_auth::ErrorPayload for JsonPathError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        stack_auth::diagnostic::payload([
            ("reason", self.reason.into()),
            ("at", (self.at as u64).into()),
        ])
    }
}

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
        // The steps are read into the path itself, so a refusal part way
        // drops a path, which wipes the keys already read.
        let mut path = Self::default();
        let segments = &mut path.segments;
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
                    let (mut key, next) = match quoted(after) {
                        Ok(parts) => parts,
                        Err(reason) => return refuse(reason, after),
                    };
                    let Some(next) = next.strip_prefix(']') else {
                        return refuse("expected `]` after the quoted name", next);
                    };
                    segments.push(Segment::Key(std::mem::take(&mut *key)));
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
        Ok(path)
    }

    /// The steps, from the root down. Empty for the root itself.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether some step is an array position (`[2]`), which a selector
    /// reads as the wildcard.
    pub fn names_a_position(&self) -> bool {
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
    /// position does not. How the JSON index's ordered paths are matched
    /// against a node's path when a document is sealed, and against a
    /// query's path when an ordering is asked.
    ///
    /// ```
    /// use stack_encrypt_jsonpath::JsonPath;
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

    /// Add one step to the end of this path. A parser reads its steps
    /// into a path with this, so the keys it has read are wiped if it
    /// refuses the text part way.
    pub fn push(&mut self, segment: Segment) {
        self.segments.push(segment);
    }
}

/// The JSON string at the front of `text`, which starts at its opening
/// quote: its value and the text after its closing quote. The escapes are
/// JSON's. The refusal is the reason; the caller names the offset.
///
/// A key is plaintext. Its value is decoded into a buffer sized for it and
/// is wiped when it is dropped, so a caller that refuses the text after it
/// leaves nothing behind. A caller that keeps the key takes it out into a
/// path, which wipes it.
fn quoted(text: &str) -> Result<(Zeroizing<String>, &str), &'static str> {
    let end = crate::json_string::string_end(text.as_bytes()).ok_or("unterminated quoted name")?;
    let key = crate::json_string::string_text(&text.as_bytes()[..=end])
        .ok_or("the quoted name is not a JSON string")?;
    Ok((key, &text[end + 1..]))
}

/// The path of these steps, from the root down.
impl From<Vec<Segment>> for JsonPath {
    fn from(segments: Vec<Segment>) -> Self {
        Self { segments }
    }
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
    fn a_path_built_step_by_step_is_the_path_parsed() {
        let mut built = JsonPath::root();
        built.push(key("visits"));
        built.push(Segment::Wildcard);
        built.push(key("place"));
        let parsed = JsonPath::parse("$.visits[*].place").unwrap();
        assert_eq!(built, parsed);
        assert_eq!(
            JsonPath::from(vec![key("visits"), Segment::Wildcard, key("place")]),
            parsed
        );
    }

    #[test]
    fn a_position_is_named_and_a_wildcard_is_not() {
        let path = |text: &str| JsonPath::parse(text).unwrap();
        assert!(path("$.a[2].b").names_a_position());
        assert!(!path("$.a[*].b").names_a_position());
        assert!(!path("$").names_a_position());
    }

    /// A refusal names its reason and offset, never the text: a key in it
    /// can be customer data.
    #[test]
    fn a_refusal_does_not_quote_the_text() {
        let error = JsonPath::parse("$.secret[x]").unwrap_err();
        assert_eq!(
            error.reason,
            "expected `*`, a quoted name or a position after `[`"
        );
        assert_eq!(error.at, 9);
        assert!(!error.to_string().contains("secret"));
    }
}
