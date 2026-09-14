//! The header micro-format of the `transport_send` host import.
//!
//! Request and response headers cross the boundary as one UTF-8 buffer of
//! `name: value` lines separated by `\n` (HTTP/1.1 field syntax, minus
//! folding) — trivially encoded and decoded on both sides without pulling
//! the value codec into the transport layer. Names compare
//! ASCII-case-insensitively, as in HTTP. Pure functions, unit-tested on the
//! native target.

/// The `user-agent` every ZeroKMS request carries.
///
/// Not optional, and not cosmetic: the edge in front of production ZeroKMS
/// refuses a request that arrives without one — and refuses a host
/// runtime's generic default too (`Go-http-client/1.1` is rejected) — with a
/// bare nginx 403 that never reaches the application. The native client sets
/// one in `stack_kms::user_agent`; the guest builds its own requests and
/// never goes through that path, so it has to say who it is here.
pub const USER_AGENT: &str = concat!(
    "stack-encrypt-guest/",
    env!("CARGO_PKG_VERSION"),
    " (wasm32-wasip1)"
);

/// The headers of a ZeroKMS request: the bearer credential, the content
/// type, and [`USER_AGENT`].
///
/// This lives here rather than at the call site because `host` is
/// `#[cfg(target_arch = "wasm32")]` and so is never compiled — let alone
/// tested — on the native target. The header set is the kind of thing that
/// fails in production and nowhere else, so it belongs in a module the test
/// suite can see.
pub fn request_headers(authorization: &str) -> Vec<u8> {
    encode_headers(&[
        ("authorization", authorization),
        ("content-type", "application/json"),
        ("user-agent", USER_AGENT),
    ])
}

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
/// Malformed lines (no colon, non-UTF-8 bytes) are skipped rather than
/// failing the response: the transport's contract is carried by the status
/// and body, and header parsing must not be a denial-of-service lever. The
/// skip is per *line*, not per buffer — a proxy that emits one raw
/// ISO-8859-1 byte in an unrelated header (a `via`/`server` line, say) must
/// not make the `content-type` lookup fail and with it every KMS call.
pub fn header_value<'a>(buffer: &'a [u8], name: &str) -> Option<&'a str> {
    buffer.split(|&b| b == b'\n').find_map(|line| {
        let line = std::str::from_utf8(line).ok()?;
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

    /// The edge in front of production ZeroKMS answers a request with no
    /// `user-agent` with a bare nginx 403, before the application sees it.
    /// Every request must carry one, and it must not be a host runtime's
    /// generic default — those are refused too.
    #[test]
    fn every_request_identifies_itself() {
        let headers = request_headers("Bearer tok");
        let ua = header_value(&headers, "user-agent").expect("requests carry a user-agent");
        assert!(
            ua.starts_with("stack-encrypt-guest/"),
            "the user-agent must name this guest, got {ua:?}"
        );
        assert!(
            !ua.contains("Go-http-client"),
            "a host runtime's default user-agent is refused by the edge"
        );
        assert_eq!(header_value(&headers, "authorization"), Some("Bearer tok"));
        assert_eq!(
            header_value(&headers, "content-type"),
            Some("application/json")
        );
    }

    #[test]
    fn a_non_utf8_line_does_not_poison_the_other_headers() {
        let mut buffer = b"server: pro".to_vec();
        buffer.push(0xe9); // "proxé" in raw ISO-8859-1
        buffer.extend_from_slice(b"\ncontent-type: application/json");
        assert_eq!(
            header_value(&buffer, "content-type"),
            Some("application/json")
        );
    }
}
