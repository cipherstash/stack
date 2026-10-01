//! The transport seam.
//!
//! [`ZeroKMSConnection`] is how the client sends a [`ViturRequest`] and gets
//! its response back. The default implementation, [`HttpConnection`], speaks
//! HTTPS via reqwest and lives behind the `http` feature. Hosts that provide
//! their own transport — the WASI/wazero guest, where HTTP is a host import —
//! implement the trait themselves and build the client with
//! [`StackKms::connect`](crate::StackKms::connect); with the `http` feature
//! off, reqwest and its native TLS stack are not in the dependency graph at
//! all.

use std::future::Future;

use zerokms_protocol::{ViturRequest, ViturRequestError};

use crate::endpoint::ZeroKmsEndpoint;

// Transport-independent: a guest built without the `http` feature classifies
// responses exactly as `HttpConnection` does.
mod classify;
pub use classify::{
    classify_response, is_json_content_type, BaseUrlUnresolved, FailureResponse,
    UnexpectedContentType,
};

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "http")]
pub use http::{ConnectionInitError, HttpConnection, HttpConnectionOpts};

pub trait ZeroKMSConnectionInit {
    type ConnectionOpts;
    type Error: std::error::Error + Send + Sync + 'static;

    fn init(opts: Self::ConnectionOpts) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// The returned future is bounded by [`MaybeSend`](crate::MaybeSend): `Send`
/// on native targets so callers can drive it on a multi-threaded runtime,
/// unbounded on wasm32 — reqwest's fetch-backed response futures aren't
/// `Send`, and edge runtimes are single-threaded anyway.
pub trait ZeroKMSConnection: ZeroKMSConnectionInit {
    fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> impl Future<Output = Result<Request::Response, ViturRequestError>> + crate::MaybeSend;

    /// Record the ZeroKMS endpoint if none is known yet.
    ///
    /// [`StackKms`](crate::StackKms) calls this with the endpoint named by the
    /// access token's `services` claim the first time it holds a token.
    ///
    /// Endpoint discovery is `StackKms` policy, not something every transport
    /// needs: the default is a no-op, paired with a `has_base_url` of `true`,
    /// which is correct for a transport that does not build URLs from a base
    /// (it dispatches on the request's endpoint name) or that was pinned at
    /// init. A transport that *does* want discovery must override **both**,
    /// and its `ensure_base_url` must keep the first value it is given — an
    /// endpoint pinned at init must not be overridden by a later token.
    fn ensure_base_url(&self, _url: ZeroKmsEndpoint) {}

    /// Whether an endpoint is known, either from init or from a previous
    /// [`ensure_base_url`](Self::ensure_base_url). While this is `false`,
    /// [`send`](Self::send) cannot build a request URL.
    ///
    /// Defaults to `true`: a transport that needs no base URL always has
    /// everything it needs, so `StackKms` never tries to resolve one from a
    /// token. Override alongside [`ensure_base_url`](Self::ensure_base_url).
    fn has_base_url(&self) -> bool {
        true
    }
}
