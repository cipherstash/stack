//! The headers this guest's ZeroKMS requests carry, over the wire format
//! every guest shares ([`stack_guest_abi::headers`]: `name: value` lines).

use std::sync::OnceLock;

use stack_guest_abi::headers::encode_headers;

/// The host this guest is driven by, as it appears in [`user_agent`].
///
/// One token, because today there is one build. `stack-encrypt-ffi` (the
/// plan in #2209) builds the same ABI crate as this WASI guest *and* as a
/// native cdylib for C, C++ and Python, at which point this becomes a
/// per-build value rather than a constant. Letting the host contribute its
/// own token as well — an application's `myapp/1.0` after ours — is a
/// deliberate follow-up: what ships now is one string this crate controls,
/// not an extension point with a single user.
const HOST: &str = "Go";

/// The `user-agent` every ZeroKMS request carries.
///
/// Not optional, and not cosmetic: the edge in front of production ZeroKMS
/// refuses a request that arrives without one — and refuses a host
/// runtime's generic default too (`Go-http-client/1.1` is rejected) — with a
/// bare nginx 403 that never reaches the application. The native client sets
/// one in `stack_kms::user_agent`; the guest builds its own requests and
/// never goes through that path, so it has to say who it is here.
///
/// It names the *library* and the host carrying it, not this crate — a
/// `stack-encrypt/0.1.0 (Go)`: the `stack-encrypt/0.1.0` product token
/// means the same thing from Rust, from here, or from a native cdylib, and
/// the guest shim's own version number would say nothing anyone reading a
/// log wants to know.
pub fn user_agent() -> &'static str {
    static USER_AGENT: OnceLock<String> = OnceLock::new();
    USER_AGENT.get_or_init(|| format!("stack-encrypt/{} ({HOST})", stack_encrypt::VERSION))
}

/// The headers of a ZeroKMS request: the bearer credential, the content
/// type, and [`user_agent`].
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
        ("user-agent", user_agent()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_guest_abi::headers::header_value;

    /// The edge in front of production ZeroKMS answers a request with no
    /// `user-agent` with a bare nginx 403, before the application sees it.
    /// Every request must carry one, and it must not be a host runtime's
    /// generic default — those are refused too.
    #[test]
    fn every_request_identifies_itself() {
        let headers = request_headers("Bearer tok");
        let ua = header_value(&headers, "user-agent").expect("requests carry a user-agent");
        assert_eq!(
            ua,
            format!("stack-encrypt/{} (Go)", stack_encrypt::VERSION),
            "the user-agent names the library and the host carrying it"
        );
        assert!(
            !ua.contains("Go-http-client"),
            "a host runtime's default user-agent is refused by the edge"
        );
        assert_eq!(
            header_value(&headers, "authorization"),
            Some("Bearer tok"),
            "the credential travels with the user-agent"
        );
        assert_eq!(
            header_value(&headers, "content-type"),
            Some("application/json"),
            "the content type travels with the user-agent"
        );
    }
}
