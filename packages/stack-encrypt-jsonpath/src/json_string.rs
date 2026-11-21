//! JSON strings: the quoted names of a path, and the strings of every JSON
//! text `stack-encrypt` reads.
//!
//! One decoder serves both, so a quoted key in a path and the same key in a
//! document decode to the same text. The escapes are JSON's. A string's
//! decoded text is never longer than its raw text, so a caller sizes the
//! buffer to [`raw_len`] before it decodes, and the buffer never grows: a
//! key can be customer data, and a buffer that grew would free a copy of
//! it.

use zeroize::Zeroizing;

/// The decoder refused the text at its cursor: a control character, the
/// end of the text before the closing quote, a malformed escape, an unpaired
/// surrogate, or bytes that are not UTF-8. The cursor is left at the place
/// the refusal names, so the caller reports the offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StringSyntaxError;

/// Decode the string whose raw text starts at `rest`, just after its
/// opening quote, into `out`, and move `rest` past its closing quote.
///
/// # Errors
///
/// [`StringSyntaxError`] for text that is not the rest of one JSON string.
/// `rest` is then at the first byte refused.
pub fn decode<'t>(rest: &mut &'t [u8], out: &mut String) -> Result<(), StringSyntaxError> {
    loop {
        // A run of plain bytes, copied as one checked UTF-8 slice.
        let current: &'t [u8] = rest;
        let run = current
            .iter()
            .take_while(|&&b| b != b'"' && b != b'\\' && b >= 0x20)
            .count();
        let (plain, tail) = current.split_at(run);
        let plain = std::str::from_utf8(plain).map_err(|_| StringSyntaxError)?;
        out.push_str(plain);
        *rest = tail;
        match rest.first() {
            Some(b'"') => {
                bump(rest);
                return Ok(());
            }
            Some(b'\\') => {
                bump(rest);
                out.push(escape(rest)?);
            }
            // A control character, or the end of the text.
            _ => return Err(StringSyntaxError),
        }
    }
}

/// Step past the next byte.
fn bump(rest: &mut &[u8]) {
    if let [_, tail @ ..] = *rest {
        *rest = tail;
    }
}

/// The character an escape names, after its backslash.
fn escape(rest: &mut &[u8]) -> Result<char, StringSyntaxError> {
    let c = match rest.first() {
        Some(b'"') => '"',
        Some(b'\\') => '\\',
        Some(b'/') => '/',
        Some(b'b') => '\u{8}',
        Some(b'f') => '\u{c}',
        Some(b'n') => '\n',
        Some(b'r') => '\r',
        Some(b't') => '\t',
        Some(b'u') => {
            bump(rest);
            return unicode(rest);
        }
        _ => return Err(StringSyntaxError),
    };
    bump(rest);
    Ok(c)
}

/// `\uXXXX`, after its `u`: one code point, or a surrogate pair. An
/// unpaired surrogate is refused.
fn unicode(rest: &mut &[u8]) -> Result<char, StringSyntaxError> {
    let high = hex4(rest)?;
    let code = if (0xD800..0xDC00).contains(&high) {
        let Some(tail) = rest.strip_prefix(b"\\u") else {
            return Err(StringSyntaxError);
        };
        *rest = tail;
        let low = hex4(rest)?;
        if !(0xDC00..0xE000).contains(&low) {
            return Err(StringSyntaxError);
        }
        0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
    } else {
        high
    };
    char::from_u32(code).ok_or(StringSyntaxError)
}

fn hex4(rest: &mut &[u8]) -> Result<u32, StringSyntaxError> {
    let current: &[u8] = rest;
    let Some((digits, tail)) = current.split_first_chunk::<4>() else {
        return Err(StringSyntaxError);
    };
    let mut code = 0;
    for &d in digits {
        let Some(v) = char::from(d).to_digit(16) else {
            return Err(StringSyntaxError);
        };
        code = code * 16 + v;
    }
    *rest = tail;
    Ok(code)
}

/// The length of a string's raw text, from after its opening quote to
/// before its closing one (or to the end, when it has none): an escaped
/// quote does not end it.
pub fn raw_len(rest: &[u8]) -> usize {
    let mut escaped = false;
    rest.iter()
        .take_while(|&&b| {
            let end = b == b'"' && !escaped;
            escaped = !escaped && b == b'\\';
            !end
        })
        .count()
}

/// The text of one JSON string, quotes included, decoded; `None` for text
/// that is not exactly one string. The decoded text is wiped when it is
/// dropped. Its buffer is sized to the raw text before anything is written,
/// so it never grows, and it is wiped on a refusal.
pub fn string_text(text: &[u8]) -> Option<Zeroizing<String>> {
    let mut rest = text.strip_prefix(b"\"")?;
    let mut decoded = Zeroizing::new(String::with_capacity(raw_len(rest)));
    decode(&mut rest, &mut decoded).ok()?;
    rest.is_empty().then_some(decoded)
}

/// Where the JSON string at the front of `text` ends: the offset of its
/// closing quote. `text` starts at the opening quote. `None` for a string
/// with no closing quote. An escaped quote does not close it.
pub fn string_end(text: &[u8]) -> Option<usize> {
    let end = 1 + raw_len(text.get(1..)?);
    (end < text.len()).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_end_is_the_offset_of_the_closing_quote() {
        for (text, end) in [
            (r#""""#, Some(1)),
            (r#""ab" rest"#, Some(3)),
            (r#""a\"b" rest"#, Some(5)),
            (r#""a\\" rest"#, Some(4)),
            (r#""a\\\"b""#, Some(7)),
            (r#""unterminated"#, None),
            (r#""ends in an escape\""#, None),
            (r#"""#, None),
            ("", None),
        ] {
            assert_eq!(string_end(text.as_bytes()), end, "{text:?}");
        }
    }

    #[test]
    fn string_text_decodes_exactly_one_json_string() {
        let decoded = |text: &str| string_text(text.as_bytes()).map(|text| text.to_string());
        assert_eq!(decoded(r#""plain""#).as_deref(), Some("plain"));
        assert_eq!(decoded(r#""""#).as_deref(), Some(""));
        assert_eq!(
            decoded(r#""a\n\"b\" é 😀""#).as_deref(),
            Some("a\n\"b\" é 😀")
        );
        for refused in [
            "",
            "plain",
            r#" "leading space""#,
            r#""unterminated"#,
            r#""one" "two""#,
            r#""trailing" "#,
            r#""bad \x escape""#,
            r#""lone \ud83d surrogate""#,
            "\"raw\nnewline\"",
            "1",
            "null",
        ] {
            assert_eq!(decoded(refused), None, "{refused:?}");
        }
    }

    /// A predicate's literals and a path's quoted keys are JSON strings by
    /// `serde_json`'s rules: every string it reads is read the same here,
    /// and every one it refuses is refused.
    #[test]
    fn string_text_reads_what_serde_json_reads() {
        for text in [
            r#""""#,
            r#""a""#,
            r#""\"\\\/\b\f\n\r\t""#,
            r#""Aé中""#,
            r#""😀""#,
            r#""\ude00\ud83d""#,
            r#""\ud83d""#,
            r#""\u12""#,
            r#""\q""#,
            "\"\u{1}\"",
            "\"é中😀\"",
            r#""a"b""#,
        ] {
            let ours = string_text(text.as_bytes()).map(|text| text.to_string());
            let theirs = serde_json::from_str::<String>(text).ok();
            assert_eq!(ours, theirs, "{text:?}");
        }
    }

    /// A refusal leaves the cursor at the byte refused, which is the offset
    /// a caller reports.
    #[test]
    fn a_refusal_leaves_the_cursor_at_the_byte_refused() {
        for (text, left) in [
            (&b"ab\x01cd"[..], &b"\x01cd"[..]),
            (b"ab", b""),
            (br"a\qb", b"qb"),
            (br"\u12g4", b"12g4"),
            (br"\ud83dx", b"x"),
            (br"\ud83d\u0041", b""),
            (b"a\xffb\"", b"a\xffb\""),
        ] {
            let mut rest = text;
            let mut out = String::new();
            assert_eq!(decode(&mut rest, &mut out), Err(StringSyntaxError));
            assert_eq!(rest, left, "{}", String::from_utf8_lossy(text));
        }
        let mut rest = &br#"a\"b" tail"#[..];
        let mut out = String::new();
        assert_eq!(decode(&mut rest, &mut out), Ok(()));
        assert_eq!((out.as_str(), rest), ("a\"b", &b" tail"[..]));
    }

    #[test]
    fn the_raw_length_runs_to_the_closing_quote_or_the_end() {
        assert_eq!(raw_len(br#"abc""#), 3);
        assert_eq!(raw_len(br#"a\"b\\""#), 6);
        assert_eq!(raw_len(b"ab"), 2, "an unterminated string runs to the end");
    }

    /// Each escape decodes to the character JSON gives it, a surrogate
    /// pair to its one code point, and the boundaries refuse what they
    /// should: a control character, a lone or reversed surrogate, a short
    /// or non-hex `\u`.
    #[test]
    fn each_escape_decodes_and_each_boundary_holds() {
        let decoded = |raw: &str| {
            let mut rest = raw.as_bytes();
            let mut out = String::new();
            decode(&mut rest, &mut out).map(|()| (out, rest.len()))
        };
        for (raw, expected) in [
            (r#"\"""#, "\""),
            (r#"\\""#, "\\"),
            (r#"\/""#, "/"),
            (r#"\b""#, "\u{8}"),
            (r#"\f""#, "\u{c}"),
            (r#"\n""#, "\n"),
            (r#"\r""#, "\r"),
            (r#"\t""#, "\t"),
            (r#"\u0041""#, "A"),
            (r#"\u00e9""#, "\u{e9}"),
            (r#"\u00E9""#, "\u{e9}"),
            (r#"\uffff""#, "\u{ffff}"),
            (r#"\ud83d\ude00""#, "\u{1f600}"),
            (r#"\ud800\udc00""#, "\u{10000}"),
            (r#"\udbff\udfff""#, "\u{10ffff}"),
            ("\u{20}~\"", " ~"),
        ] {
            assert_eq!(decoded(raw), Ok((expected.to_owned(), 0)), "{raw:?}");
        }
        for raw in [
            "\u{1f}\"",
            r#"\ud83d""#,
            r#"\ud83d\u0041""#,
            r#"\ud83d\ue000""#,
            r#"\udc00""#,
            r#"\u12""#,
            r#"\u12g4""#,
            r#"\x""#,
            r#"\"#,
        ] {
            assert_eq!(decoded(raw).ok(), None, "{raw:?}");
        }
        assert_eq!(decoded(r#"ab" tail"#), Ok(("ab".to_owned(), 5)));
    }

    #[test]
    fn an_escaped_backslash_does_not_escape_the_quote_after_it() {
        assert_eq!(raw_len(br#"a\\"b"#), 3);
        assert_eq!(raw_len(br#"a\\\"b""#), 6);
        assert_eq!(string_end(br#""a\\" rest"#), Some(4));
        assert_eq!(string_end(b"\""), None, "an opening quote alone");
        assert_eq!(string_end(b"\"\""), Some(1));
    }
}
