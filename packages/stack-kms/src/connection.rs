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
    /// Send `request` with `access_token` as its bearer credential.
    ///
    /// `endpoint` is the ZeroKMS [`StackKms`](crate::StackKms) resolved from
    /// the token's `services` claim, and is `Some` only while
    /// [`has_base_url`](Self::has_base_url) is `false`. A connection with an
    /// endpoint of its own uses that and ignores this one; a connection with
    /// neither cannot build a request URL and should fail with a *prepare*
    /// error ([`BaseUrlUnresolved`]), so a caller does not mistake it for a
    /// 401 and refresh in a loop.
    ///
    /// The endpoint travels with each request rather than being stored on the
    /// connection: `StackKms` keeps one only after ZeroKMS has accepted a
    /// token sent there, so a token it refuses cannot fix the endpoint every
    /// later request goes to.
    fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
        endpoint: Option<&ZeroKmsEndpoint>,
    ) -> impl Future<Output = Result<Request::Response, ViturRequestError>> + crate::MaybeSend;

    /// Whether the connection was given its ZeroKMS endpoint at init.
    ///
    /// While this is `false`, [`StackKms`](crate::StackKms) resolves the
    /// endpoint from each access token's `services` claim and passes it to
    /// [`send`](Self::send). It is asked once, when the client is built.
    ///
    /// Defaults to `true`, which is correct for a transport that does not
    /// build URLs from a base (it dispatches on the request's endpoint name)
    /// or that was configured with one: `StackKms` never consults the claim.
    fn has_base_url(&self) -> bool {
        true
    }
}
