//! The headers this guest's auth requests carry, over the wire format every
//! guest shares ([`stack_guest_abi::headers`]: `name: value` lines).
//!
//! stack-auth builds each request, `user-agent` included; this module is the
//! one change the guest makes on the way to the host: it names the host.

use std::sync::OnceLock;

use stack_guest_abi::headers::encode_headers;

/// The host this guest is driven by, as it appears in [`user_agent`]. One
/// token for one build, as in the crypto guest's `headers` module.
const HOST: &str = "Go";

/// The `user-agent` every auth request from this guest carries:
/// `stack-auth/<version> (Go)`.
///
/// Not optional, and not cosmetic: the edge in front of production CTS
/// refuses a host runtime's generic default (`Go-http-client/1.1`, which
/// Go's HTTP client fills in when a request carries none) with a bare nginx
/// 403 that never reaches CTS.
///
/// stack-auth already sets one, `stack-auth/<version> (<os> <arch>)`, and
/// this replaces it rather than passing it through. Built for wasm32-wasip1
/// that value would read `(wasi wasm32)`: true of the sandbox, useless to
/// anyone reading a log, and silent about the host that actually made the
/// request. The crypto guest's `stack-encrypt/<version> (Go)` names the
/// library and the host carrying it; this says the same of stack-auth, with
/// stack-auth's own version, so the product token means one thing from Rust
/// and from Go.
pub fn user_agent() -> &'static str {
    static USER_AGENT: OnceLock<String> = OnceLock::new();
    USER_AGENT.get_or_init(|| format!("stack-auth/{} ({HOST})", stack_auth::VERSION))
}

/// `headers` (a stack-auth request's) in the host's wire format, with its
/// `user-agent` replaced by [`user_agent`]. Every other header crosses as
/// stack-auth built it, in order.
///
/// This lives here rather than in `host` because `host` is
/// `#[cfg(target_arch = "wasm32")]` and so is never compiled, let alone
/// tested, on the native target. The header set is the kind of thing that
/// fails in production and nowhere else.
pub fn request_headers(headers: &[(String, String)]) -> Vec<u8> {
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("user-agent"))
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .chain(std::iter::once(("user-agent", user_agent())))
        .collect();
    encode_headers(&pairs)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures::executor::block_on;
    use stack_auth::{
        AccessKeyStrategy, AuthStrategy, HttpRequest, HttpResponse, HttpTransport, RequestError,
    };
    use stack_guest_abi::headers::header_value;

    use super::*;

    /// Captures the headers of every request stack-auth builds, as this
    /// guest would hand them to the host, and answers with a 500.
    #[derive(Default)]
    struct Capture(Mutex<Vec<Vec<u8>>>);

    impl HttpTransport for Capture {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            self.0
                .lock()
                .unwrap()
                .push(request_headers(request.headers()));
            Ok(HttpResponse::new(500, Vec::new(), Vec::new()))
        }
    }

    fn user_agent_lines(headers: &[u8]) -> usize {
        std::str::from_utf8(headers)
            .unwrap()
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("user-agent:"))
            .count()
    }

    /// The edge in front of production CTS answers a request whose
    /// `user-agent` is Go's default with a bare nginx 403, before CTS sees
    /// it. Every request this guest hands the host must name the library
    /// and the host, once, and keep the headers stack-auth built.
    #[test]
    fn every_request_identifies_itself() {
        let capture = Arc::new(Capture::default());
        let strategy = AccessKeyStrategy::builder(
            "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap(),
            "CSAKtestKeyId.testKeySecret".parse().unwrap(),
        )
        .base_url("https://cts.example.com/".parse().unwrap())
        .transport(Arc::clone(&capture))
        .build()
        .unwrap();
        let _ = block_on((&strategy).get_token());

        let seen = capture.0.lock().unwrap();
        assert_eq!(seen.len(), 1, "one access-key exchange");
        let headers = &seen[0];
        let ua = header_value(headers, "user-agent").expect("requests carry a user-agent");
        assert_eq!(
            ua,
            format!("stack-auth/{} (Go)", stack_auth::VERSION),
            "the user-agent names the library and the host carrying it"
        );
        assert!(
            !ua.contains("Go-http-client"),
            "a host runtime's default user-agent is refused by the edge"
        );
        assert_eq!(
            user_agent_lines(headers),
            1,
            "stack-auth's own user-agent is replaced, not sent alongside: {:?}",
            String::from_utf8_lossy(headers)
        );
        assert_eq!(
            header_value(headers, "content-type"),
            Some("application/json"),
            "the content type travels with the user-agent"
        );
    }

    #[test]
    fn a_user_agent_is_replaced_whatever_its_case_and_the_rest_kept_in_order() {
        let headers = request_headers(&[
            ("authorization".into(), "Bearer tok".into()),
            ("User-Agent".into(), "stack-auth/0.0.0 (wasi wasm32)".into()),
            ("content-type".into(), "application/json".into()),
        ]);
        assert_eq!(
            String::from_utf8(headers).unwrap(),
            format!(
                "authorization: Bearer tok\ncontent-type: application/json\nuser-agent: {}",
                user_agent()
            )
        );
    }
}
