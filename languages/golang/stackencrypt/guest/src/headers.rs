//! The header micro-format of the `transport_send` host import.
//!
//! Request and response headers cross the boundary as one UTF-8 buffer of
//! `name: value` lines separated by `\n` (HTTP/1.1 field syntax, minus
//! folding) — trivially encoded and decoded on both sides without pulling
//! the value codec into the transport layer. Names compare
//! ASCII-case-insensitively, as in HTTP. Pure functions, unit-tested on the
//! native target.

/// Encode header pairs as the wire buffer.
pub fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::new();
    for (i, (name, value)) in headers.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
    }
    out.into_bytes()
}

/// Look up a header by (ASCII-case-insensitive) name in a wire buffer.
/// Malformed lines (no colon, non-UTF-8 buffer) are skipped rather than
/// failing the response: the transport's contract is carried by the status
/// and body, and header parsing must not be a denial-of-service lever.
pub fn header_value<'a>(buffer: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(buffer).ok()?;
    text.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_matches_case_insensitively() {
        let buffer = encode_headers(&[
            ("authorization", "Bearer tok"),
            ("content-type", "application/json"),
        ]);
        assert_eq!(
            std::str::from_utf8(&buffer).unwrap(),
            "authorization: Bearer tok\ncontent-type: application/json"
        );
        assert_eq!(
            header_value(&buffer, "Content-Type"),
            Some("application/json")
        );
        assert_eq!(header_value(&buffer, "authorization"), Some("Bearer tok"));
        assert_eq!(header_value(&buffer, "x-missing"), None);
    }

    #[test]
    fn tolerates_whitespace_and_skips_malformed_lines() {
        assert_eq!(
            header_value(b"Content-Type:  text/html \ngarbage-line", "content-type"),
            Some("text/html")
        );
        assert_eq!(header_value(b"no colon here", "content-type"), None);
        assert_eq!(header_value(&[0xff, 0xfe], "content-type"), None);
        assert_eq!(header_value(b"", "content-type"), None);
    }
}
