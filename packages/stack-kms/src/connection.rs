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
    /// access token's `services` claim the first time it holds a token. A
    /// connection that was pinned to an endpoint at init keeps it — the first
    /// value wins — so callers can override discovery without racing it.
    fn ensure_base_url(&self, url: ZeroKmsEndpoint);

    /// Whether an endpoint is known, either from init or from a previous
    /// [`ensure_base_url`](Self::ensure_base_url). While this is `false`,
    /// [`send`](Self::send) cannot build a request URL.
    fn has_base_url(&self) -> bool;
}
