//! JSON text at the engine's boundary: how a language SDK hands the JSON
//! index a document, and how it gets one back.
//!
//! A binding has no `serde_json::Value` to pass. It sends the document as
//! UTF-8 JSON text, and the engine parses it here, once, by one set of
//! rules, so every language seals the same document for the same text:
//!
//! - **Numbers** are signed or unsigned 64-bit integers, or binary64
//!   floats. An integer literal (no fraction, no exponent) outside
//!   `i64::MIN ..= u64::MAX` is refused ([`JsonTextError::IntegerRange`])
//!   rather than read as the nearest `f64`, which would seal a different
//!   number than the text names. A literal with a fraction or an exponent
//!   is the nearest binary64 (correctly rounded, as serde_json's
//!   `float_roundtrip` parser reads it), so
//!   `1e400` is refused as not JSON this engine reads, and `0.1` is the
//!   double nearest to it.
//! - **An object names each member once.** A repeated key is refused
//!   ([`JsonTextError::DuplicateKey`]) rather than resolved, since two JSON
//!   parsers keep different ones (Go's `encoding/json` the last, others the
//!   first) and the sealed document would depend on which ran.
//! - **Text is valid Unicode**: invalid UTF-8 and an unpaired surrogate
//!   escape (`"\ud800"`) are refused as not JSON.
//! - **Nesting** is limited by the parser (127 levels of containers,
//!   serde_json's limit) and by the index
//!   ([`TermError::JsonTooDeep`](crate::sem::TermError::JsonTooDeep)).
//!
//! What comes back out ([`to_text`]) is JSON text serde_json writes:
//! numbers in their shortest round-tripping form, members in the order the
//! document holds them. Key order, whitespace and the spelling of a number
//! (`1.0`, `1e0`) are not promised to survive: the document is sealed as
//! values, not as text.
//!
//! Every error names a class and, for a syntax error, a line and column,
//! and never a byte of the text.

use serde_json::{Map, Number, Value};
use zeroize::Zeroize;

/// Why JSON text was refused at the boundary. Each says what kind of
/// mistake it was and where, never what the text held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonTextError {
    /// Not JSON text: a syntax error, text that is not UTF-8, an unpaired
    /// surrogate, a float out of range, nesting past the parser's limit, or
    /// anything after the value.
    #[error("not JSON text (line {line}, column {column})")]
    Syntax {
        /// The line of the first byte refused, from 1.
        line: usize,
        /// Its column, from 1.
        column: usize,
    },
    /// An object names one member twice.
    #[error("an object names a member twice (line {line}, column {column})")]
    DuplicateKey {
        /// The line of the second name, from 1.
        line: usize,
        /// Its column, from 1.
        column: usize,
    },
    /// An integer literal outside the signed and unsigned 64-bit range.
    #[error("an integer literal is outside the 64-bit range")]
    IntegerRange,
}

impl JsonTextError {
    /// The error's machine-readable code: `json_syntax`,
    /// `json_duplicate_key` or `json_integer_range`.
    pub fn code(&self) -> &'static str {
        match self {
            JsonTextError::Syntax { .. } => "json_syntax",
            JsonTextError::DuplicateKey { .. } => "json_duplicate_key",
            JsonTextError::IntegerRange => "json_integer_range",
        }
    }
}

/// Parse a document from UTF-8 JSON text by the rules in the module docs.
///
/// The parser is the engine's own, not serde_json's deserializer, so that
/// it leaves no string and no array buffer in a heap block it frees: each
/// string is decoded into a buffer sized for it before it is read, so it
/// never grows; an array's buffer is wiped before it is replaced by a
/// larger one; numbers are read from the text in place; and on a refusal
/// the part of the document built so far is wiped
/// ([`wipe_value`](super::wipe_value)) before it drops.
///
/// An object's members go into serde_json's map, a `BTreeMap`, which
/// splits a full node by copying half its members to a new one and does
/// not clear the slots it leaves. Strings move by pointer, so their bytes
/// never sit in those slots, but a number or a boolean is held inline: in
/// an object of twelve or more members, a scalar member's value can stay
/// in a node the map frees. Numbers and booleans are wiped best-effort, as
/// [`wipe_value`](super::wipe_value) says.
///
/// # Errors
///
/// [`JsonTextError`]: the text is not JSON, an object repeats a member,
/// or an integer literal is out of range.
///
/// ```
/// use stack_encrypt::json::{parse_text, JsonTextError};
///
/// let value = parse_text(br#"{"name": "Alice", "age": 34}"#)?;
/// assert_eq!(value["age"], 34);
/// assert!(matches!(parse_text(br#"{"a": 1, "a": 2}"#), Err(JsonTextError::DuplicateKey { .. })));
/// assert_eq!(parse_text(b"18446744073709551616"), Err(JsonTextError::IntegerRange));
/// # Ok::<(), JsonTextError>(())
/// ```
pub fn parse_text(text: &[u8]) -> Result<Value, JsonTextError> {
    let mut parser = Parser { text, rest: text };
    let mut value = parser.value(MAX_DEPTH)?;
    parser.skip_whitespace();
    if !parser.rest.is_empty() {
        super::wipe_value(&mut value);
        return Err(parser.syntax());
    }
    Ok(value)
}

/// The document as JSON text: what opening returns to a binding. The
/// buffer is sized from the text's length before it is written, so it is
/// never reallocated and no freed block holds part of it.
///
/// # Errors
///
/// None in practice: every `Value` serializes. The `Result` is serde_json's.
pub fn to_text(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    let mut text = Vec::with_capacity(counter.0);
    serde_json::to_writer(&mut text, value)?;
    Ok(text)
}

/// A writer that counts the bytes it is given and keeps none.
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How deep containers nest: serde_json's limit, so a document either
/// parser reads, the other reads too.
const MAX_DEPTH: usize = 127;

/// The parser's place: the whole text, for reporting a position, and the
/// part not read yet. It moves by re-slicing `rest`, never by index
/// arithmetic.
struct Parser<'t> {
    text: &'t [u8],
    rest: &'t [u8],
}

impl<'t> Parser<'t> {
    /// A syntax error at the first byte not read.
    fn syntax(&self) -> JsonTextError {
        self.syntax_at(self.rest)
    }

    /// A syntax error at the first byte of `at`, a tail of the text.
    fn syntax_at(&self, at: &[u8]) -> JsonTextError {
        let (line, column) = self.place(at);
        JsonTextError::Syntax { line, column }
    }

    /// The line and column, from 1, of the first byte of `at`, a tail of
    /// the text (the end, for an empty one).
    fn place(&self, at: &[u8]) -> (usize, usize) {
        let before = &self.text[..self.text.len() - at.len()];
        let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
        let column = before.iter().rev().take_while(|&&b| b != b'\n').count() + 1;
        (line, column)
    }

    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Step past the next byte, which the caller has peeked.
    fn bump(&mut self) {
        if let [_, tail @ ..] = self.rest {
            self.rest = tail;
        }
    }

    fn skip_whitespace(&mut self) {
        while let [b' ' | b'\t' | b'\n' | b'\r', tail @ ..] = self.rest {
            self.rest = tail;
        }
    }

    /// One value, after any whitespace, nested at most `depth` more levels.
    fn value(&mut self, depth: usize) -> Result<Value, JsonTextError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            _ => Err(self.syntax()),
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, JsonTextError> {
        match self.rest.strip_prefix(word) {
            Some(tail) => {
                self.rest = tail;
                Ok(value)
            }
            None => Err(self.syntax()),
        }
    }

    /// A container's opening byte, consumed, at one level less depth.
    fn open(&mut self, depth: usize) -> Result<usize, JsonTextError> {
        let Some(inner) = depth.checked_sub(1) else {
            return Err(self.syntax());
        };
        self.bump();
        Ok(inner)
    }

    /// After a container's member: a comma, or `close` to end it.
    fn next_or_close(&mut self, close: u8) -> Result<bool, JsonTextError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b',') => {
                self.bump();
                Ok(true)
            }
            Some(byte) if byte == close => {
                self.bump();
                Ok(false)
            }
            _ => Err(self.syntax()),
        }
    }

    /// Whether the container is empty, consuming its `close` if so.
    fn empty(&mut self, close: u8) -> bool {
        self.skip_whitespace();
        if self.peek() == Some(close) {
            self.bump();
            return true;
        }
        false
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonTextError> {
        let inner = self.open(depth)?;
        let mut items = Vec::new();
        let result = self.items(inner, &mut items);
        let mut value = Value::Array(items);
        match result {
            Ok(()) => Ok(value),
            Err(error) => {
                super::wipe_value(&mut value);
                Err(error)
            }
        }
    }

    fn items(&mut self, depth: usize, items: &mut Vec<Value>) -> Result<(), JsonTextError> {
        if self.empty(b']') {
            return Ok(());
        }
        loop {
            push_wiping(items, self.value(depth)?);
            if !self.next_or_close(b']')? {
                return Ok(());
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonTextError> {
        let inner = self.open(depth)?;
        let mut members = Map::new();
        let result = self.members(inner, &mut members);
        let mut value = Value::Object(members);
        match result {
            Ok(()) => Ok(value),
            Err(error) => {
                super::wipe_value(&mut value);
                Err(error)
            }
        }
    }

    fn members(
        &mut self,
        depth: usize,
        members: &mut Map<String, Value>,
    ) -> Result<(), JsonTextError> {
        if self.empty(b'}') {
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.syntax());
            }
            let name = self.rest;
            let mut key = self.string()?;
            if members.contains_key(&key) {
                key.zeroize();
                // The place of the name's closing quote, as serde_json
                // reports it: the last byte the name took.
                let quote = &name[name.len() - self.rest.len() - 1..];
                let (line, column) = self.place(quote);
                return Err(JsonTextError::DuplicateKey { line, column });
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                key.zeroize();
                return Err(self.syntax());
            }
            self.bump();
            match self.value(depth) {
                Ok(value) => {
                    let _ = members.insert(key, value);
                }
                Err(error) => {
                    key.zeroize();
                    return Err(error);
                }
            }
            if !self.next_or_close(b'}')? {
                return Ok(());
            }
        }
    }

    /// A string, from its opening quote. Its decoded text is never longer
    /// than its raw text, so the buffer is sized to that before anything is
    /// written and never grows; on a refusal it is wiped.
    fn string(&mut self) -> Result<String, JsonTextError> {
        self.bump();
        let mut out = String::with_capacity(raw_len(self.rest));
        match self.decode(&mut out) {
            Ok(()) => Ok(out),
            Err(error) => {
                out.zeroize();
                Err(error)
            }
        }
    }

    fn decode(&mut self, out: &mut String) -> Result<(), JsonTextError> {
        loop {
            // A run of plain bytes, copied as one checked UTF-8 slice.
            let run = self
                .rest
                .iter()
                .take_while(|&&b| b != b'"' && b != b'\\' && b >= 0x20)
                .count();
            let (plain, tail) = self.rest.split_at(run);
            let plain = std::str::from_utf8(plain).map_err(|_| self.syntax())?;
            out.push_str(plain);
            self.rest = tail;
            match self.peek() {
                Some(b'"') => {
                    self.bump();
                    return Ok(());
                }
                Some(b'\\') => {
                    self.bump();
                    out.push(self.escape()?);
                }
                // A control character, or the end of the text.
                _ => return Err(self.syntax()),
            }
        }
    }

    /// The character an escape names, after its backslash.
    fn escape(&mut self) -> Result<char, JsonTextError> {
        let c = match self.peek() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.bump();
                return self.unicode();
            }
            _ => return Err(self.syntax()),
        };
        self.bump();
        Ok(c)
    }

    /// `\uXXXX`, after its `u`: one code point, or a surrogate pair. An
    /// unpaired surrogate is refused.
    fn unicode(&mut self) -> Result<char, JsonTextError> {
        let high = self.hex4()?;
        let code = if (0xD800..0xDC00).contains(&high) {
            let Some(tail) = self.rest.strip_prefix(b"\\u") else {
                return Err(self.syntax());
            };
            self.rest = tail;
            let low = self.hex4()?;
            if !(0xDC00..0xE000).contains(&low) {
                return Err(self.syntax());
            }
            0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
        } else {
            high
        };
        char::from_u32(code).ok_or_else(|| self.syntax())
    }

    fn hex4(&mut self) -> Result<u32, JsonTextError> {
        let Some((digits, tail)) = self.rest.split_first_chunk::<4>() else {
            return Err(self.syntax());
        };
        let mut code = 0;
        for &d in digits {
            let Some(v) = char::from(d).to_digit(16) else {
                return Err(self.syntax());
            };
            code = code * 16 + v;
        }
        self.rest = tail;
        Ok(code)
    }

    /// A number, read from the text in place: an integer literal is a
    /// signed or unsigned 64-bit integer or refused, and one with a
    /// fraction or an exponent is the nearest binary64 (std's parser,
    /// correctly rounded, as serde_json's `float_roundtrip` is).
    fn number(&mut self) -> Result<Value, JsonTextError> {
        let start = self.rest;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.syntax()),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            self.bump();
            self.some_digits()?;
            float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            self.some_digits()?;
            float = true;
        }
        let token = &start[..start.len() - self.rest.len()];
        // ASCII by the grammar just read.
        let token = std::str::from_utf8(token).map_err(|_| self.syntax_at(start))?;
        let number = if float {
            token
                .parse::<f64>()
                .ok()
                .and_then(Number::from_f64)
                .ok_or_else(|| self.syntax_at(start))?
        } else if !negative {
            Number::from(
                token
                    .parse::<u64>()
                    .map_err(|_| JsonTextError::IntegerRange)?,
            )
        } else {
            match token
                .parse::<i64>()
                .map_err(|_| JsonTextError::IntegerRange)?
            {
                // serde_json reads `-0` as the float negative zero.
                0 => Number::from_f64(-0.0).ok_or_else(|| self.syntax_at(start))?,
                n => Number::from(n),
            }
        };
        Ok(Value::Number(number))
    }

    fn digits(&mut self) {
        while let [b'0'..=b'9', tail @ ..] = self.rest {
            self.rest = tail;
        }
    }

    /// At least one digit.
    fn some_digits(&mut self) -> Result<(), JsonTextError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.syntax());
        }
        self.digits();
        Ok(())
    }
}

/// The length of a string's raw text, from after its opening quote to
/// before its closing one (or to the end, when it has none): an escaped
/// quote does not end it.
fn raw_len(rest: &[u8]) -> usize {
    let mut escaped = false;
    rest.iter()
        .take_while(|&&b| {
            let end = b == b'"' && !escaped;
            escaped = !escaped && b == b'\\';
            !end
        })
        .count()
}

/// Push onto `items`, wiping the old buffer when it is replaced by a larger
/// one: the values it held were moved, but their bytes (a number, the
/// pointer and length of a string) stay in the freed block otherwise.
fn push_wiping(items: &mut Vec<Value>, value: Value) {
    // Full when there is no spare capacity; asked of the buffer rather
    // than compared, so a mutation of the test cannot make every push grow
    // it (and wipe ever larger buffers) instead of failing.
    if items.spare_capacity_mut().is_empty() {
        let mut grown = Vec::with_capacity(items.capacity().saturating_mul(2).max(4));
        grown.append(items);
        items.spare_capacity_mut().zeroize();
        *items = grown;
    }
    items.push(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_every_kind_of_value() {
        let value = parse_text(
            br#"{"s": "x", "n": -3, "u": 18446744073709551615, "f": 1.5, "b": true, "z": null, "a": [1, {}]}"#,
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"s": "x", "n": -3, "u": 18446744073709551615u64, "f": 1.5, "b": true, "z": null, "a": [1, {}]})
        );
        assert_eq!(parse_text(b" null ").unwrap(), Value::Null);
        assert_eq!(parse_text(b"\"text\"").unwrap(), json!("text"));
    }

    #[test]
    fn the_64_bit_bounds_are_integers_and_one_past_is_refused() {
        assert_eq!(
            parse_text(b"-9223372036854775808").unwrap(),
            json!(i64::MIN)
        );
        assert_eq!(
            parse_text(b"18446744073709551615").unwrap(),
            json!(u64::MAX)
        );
        for text in [
            &b"-9223372036854775809"[..],
            b"18446744073709551616",
            br#"{"a": [1, 99999999999999999999]}"#,
        ] {
            assert_eq!(parse_text(text), Err(JsonTextError::IntegerRange));
        }
        // With a fraction or an exponent it is a float, by the documented
        // binary64 rule.
        assert_eq!(parse_text(b"1e20").unwrap(), json!(1e20));
        assert_eq!(
            parse_text(b"18446744073709551616.0").unwrap(),
            json!(1.8446744073709552e19)
        );
    }

    #[test]
    fn a_long_number_inside_a_string_is_text_and_one_after_it_is_checked() {
        // Thirty digits: any suffix of them is out of range too, so a scan
        // that left the string early would refuse it.
        let text = br#"["123456789012345678901234567890", "\\", 99999999999999999999]"#;
        assert_eq!(parse_text(text), Err(JsonTextError::IntegerRange));
        assert_eq!(
            parse_text(br#"["123456789012345678901234567890", "\\"]"#).unwrap(),
            json!(["123456789012345678901234567890", "\\"])
        );
    }

    #[test]
    fn an_unterminated_string_or_a_lone_sign_is_the_parsers_to_refuse() {
        for text in [&b"\"abc"[..], b"\"ab\\", b"-", b"[1-2]", b"--1"] {
            assert!(
                matches!(parse_text(text), Err(JsonTextError::Syntax { .. })),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_number_inside_a_string_is_text() {
        assert_eq!(
            parse_text(br#"{"k": "99999999999999999999", "e": "a\"99999999999999999999"}"#)
                .unwrap()["k"],
            json!("99999999999999999999")
        );
    }

    #[test]
    fn a_repeated_member_is_refused_with_its_place() {
        assert_eq!(
            parse_text(b"{\"a\": 1,\n \"a\": 2}"),
            Err(JsonTextError::DuplicateKey { line: 2, column: 4 })
        );
        assert!(matches!(
            parse_text(br#"[{"x": {"y": 1, "y": 1}}]"#),
            Err(JsonTextError::DuplicateKey { .. })
        ));
        // The same name in two objects is two members.
        assert!(parse_text(br#"[{"a": 1}, {"a": 2}]"#).is_ok());
    }

    #[test]
    fn text_that_is_not_json_is_refused_without_quoting_it() {
        for text in [
            &b""[..],
            b"{",
            b"{\"secret-4242\"}",
            b"[1] [2]",
            b"\"\\ud800\"",
            b"\"\xff\"",
            b"1e400",
            b"NaN",
        ] {
            let error = parse_text(text).unwrap_err();
            assert!(matches!(error, JsonTextError::Syntax { .. }), "{error:?}");
            assert!(!error.to_string().contains("4242"));
            assert_eq!(error.code(), "json_syntax");
        }
    }

    #[test]
    fn text_round_trips_by_value() {
        let value = parse_text(br#"{"b": 1.0, "a": [0.1, -0.0]}"#).unwrap();
        let text = to_text(&value).unwrap();
        assert_eq!(parse_text(&text).unwrap(), value);
    }

    #[test]
    fn escapes_and_unicode_decode_as_serde_json_reads_them() {
        let text = r#"["\"\\\/\b\f\n\r\t", "\u00e9\u4e2d", "\ud83d\ude00", "é中😀", "a\u0000b"]"#
            .as_bytes();
        assert_eq!(
            parse_text(text).unwrap(),
            serde_json::from_slice::<Value>(text).unwrap()
        );
        for bad in [
            &br#""\ud800""#[..],
            br#""\ud800A""#,
            br#""\udc00""#,
            br#""\x""#,
            br#""\u12""#,
            br#""\u12g4""#,
            b"\"a\nb\"",
            b"\"\x01\"",
            b"\"\\",
        ] {
            assert!(
                matches!(parse_text(bad), Err(JsonTextError::Syntax { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn numbers_read_as_serde_json_reads_them() {
        for text in [
            &b"0"[..],
            b"-0",
            b"-0.0",
            b"1.5e3",
            b"1E-2",
            b"2e+2",
            b"0.1",
            b"-9223372036854775808",
            b"18446744073709551615",
            b"123456789012345678.5",
            b"5e-324",
            b"1e-400",
        ] {
            let ours = parse_text(text).unwrap();
            let theirs: Value = serde_json::from_slice(text).unwrap();
            assert_eq!(ours, theirs, "{}", String::from_utf8_lossy(text));
            assert_eq!(
                ours.as_f64().map(f64::to_bits),
                theirs.as_f64().map(f64::to_bits),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        for bad in [
            &b"01"[..],
            b"-",
            b"1.",
            b".5",
            b"1e",
            b"1e+",
            b"+1",
            b"0x1",
            b"--1",
            b"1.e2",
        ] {
            assert!(
                matches!(parse_text(bad), Err(JsonTextError::Syntax { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn nesting_stops_at_serde_jsons_limit() {
        let deep = |n: usize| [vec![b'['; n], vec![b']'; n]].concat();
        assert!(parse_text(&deep(127)).is_ok());
        assert!(serde_json::from_slice::<Value>(&deep(127)).is_ok());
        assert!(matches!(
            parse_text(&deep(128)),
            Err(JsonTextError::Syntax { .. })
        ));
        assert!(serde_json::from_slice::<Value>(&deep(128)).is_err());
        let objects = |n: usize| [b"{\"a\":".repeat(n), b"1".to_vec(), vec![b'}'; n]].concat();
        assert!(parse_text(&objects(127)).is_ok());
        assert!(parse_text(&objects(128)).is_err());
    }

    #[test]
    fn literals_and_structure_are_strict() {
        for bad in [
            &b"tru"[..],
            b"nul",
            b"falsey",
            b"[1,]",
            b"[1 2]",
            b"{\"a\" 1}",
            b"{\"a\":1,}",
            b"{1:1}",
            b"{\"a\":1 \"b\":2}",
            b"[1}",
            b"{\"a\":1]",
            b"[",
            b"{",
            b"{\"a\":",
            b"]",
        ] {
            assert!(
                matches!(parse_text(bad), Err(JsonTextError::Syntax { .. })),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_text(b" \t\r\n[ true , false , null ] ").unwrap(),
            json!([true, false, null])
        );
        assert_eq!(parse_text(b"{ }").unwrap(), json!({}));
        assert_eq!(parse_text(b"[ ]").unwrap(), json!([]));
    }

    #[test]
    fn a_syntax_error_names_its_line_and_column() {
        assert_eq!(
            parse_text(b"[1,\n  x]"),
            Err(JsonTextError::Syntax { line: 2, column: 3 })
        );
        assert_eq!(
            parse_text(b"?"),
            Err(JsonTextError::Syntax { line: 1, column: 1 })
        );
    }

    #[test]
    fn long_arrays_grow_and_keep_their_order() {
        let many: Vec<u32> = (0..100).collect();
        let text = serde_json::to_vec(&many).unwrap();
        assert_eq!(parse_text(&text).unwrap(), json!(many));
    }

    #[test]
    fn to_text_writes_exactly_its_length() {
        let value = json!({"name": "Alice \"A\" \u{e9}", "n": [1.5, -2, 18446744073709551615u64]});
        let text = to_text(&value).unwrap();
        assert_eq!(text.len(), text.capacity(), "sized before it is written");
        assert_eq!(text, serde_json::to_vec(&value).unwrap());
    }

    #[test]
    fn a_string_is_decoded_into_a_buffer_its_raw_length() {
        // The buffer is sized once, to the raw text between the quotes, so
        // it never grows: an escaped quote does not end the count.
        for (text, raw) in [
            (&br#""abc""#[..], 3),
            (br#""a\"b\\""#, 6),
            (br#""\u00e9x""#, 7),
            (br#""""#, 0),
        ] {
            let Value::String(decoded) = parse_text(text).unwrap() else {
                panic!("a string")
            };
            assert_eq!(decoded.capacity(), raw, "{}", String::from_utf8_lossy(text));
        }
        assert_eq!(raw_len(b"ab"), 2, "an unterminated string runs to the end");
    }

    #[test]
    fn an_array_grows_by_doubling_from_four() {
        let mut items = Vec::new();
        let mut capacities = Vec::new();
        for n in 0..9 {
            push_wiping(&mut items, json!(n));
            capacities.push(items.capacity());
        }
        assert_eq!(capacities, [4, 4, 4, 4, 8, 8, 8, 8, 16]);
        assert_eq!(items, (0..9).map(|n| json!(n)).collect::<Vec<_>>());
    }

    mod differential {
        use super::*;
        use proptest::prelude::*;

        fn document() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::Bool),
                any::<i64>().prop_map(|n| json!(n)),
                any::<u64>().prop_map(|n| json!(n)),
                any::<f64>()
                    .prop_filter("finite", |f| f.is_finite())
                    .prop_map(|f| json!(f)),
                any::<String>().prop_map(Value::String),
            ];
            leaf.prop_recursive(4, 32, 6, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                    prop::collection::btree_map(any::<String>(), inner, 0..6)
                        .prop_map(|m| Value::Object(m.into_iter().collect())),
                ]
            })
        }

        proptest! {
            /// Every document serde_json writes, compact or pretty, reads
            /// back to the same value, numbers to the same bits.
            #[test]
            fn reads_what_serde_json_writes(value in document()) {
                for text in [serde_json::to_vec(&value).unwrap(), serde_json::to_vec_pretty(&value).unwrap()] {
                    prop_assert_eq!(&parse_text(&text).unwrap(), &value);
                }
            }

            /// Over text near JSON: whatever this parser reads, serde_json
            /// reads to the same value; whatever serde_json reads and this
            /// one refuses is a repeated member or an integer out of range.
            #[test]
            fn agrees_with_serde_json_on_arbitrary_text(text in r#"[\[\]{}",:0-9eE.+\- tfrunlasa\\\\u]{0,24}"#) {
                let ours = parse_text(text.as_bytes());
                let theirs = serde_json::from_slice::<Value>(text.as_bytes());
                match (ours, theirs) {
                    (Ok(ours), Ok(theirs)) => prop_assert_eq!(ours, theirs),
                    (Ok(ours), Err(_)) => prop_assert!(false, "read {} that serde_json refuses", ours),
                    (Err(JsonTextError::Syntax { .. }), Ok(theirs)) => {
                        prop_assert!(false, "refused {:?} that serde_json reads as {}", text, theirs)
                    }
                    _ => {}
                }
            }
        }
    }
}
