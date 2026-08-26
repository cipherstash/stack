//! The single place holding this crate's native/wasm32 `Send` split.
//!
//! Async traits here ([`DataKeySource`](crate::DataKeySource),
//! [`IndexKeySource`](crate::IndexKeySource),
//! [`ZeroKMSConnection`](crate::ZeroKMSConnection)) want their returned
//! futures `Send` on native targets — so callers can drive them on a
//! multi-threaded runtime — but not on wasm32, where the fetch-backed HTTP and
//! auth futures aren't `Send` and edge runtimes are single-threaded anyway
//! (mirroring `stack_auth::AuthStrategy`). Bounding those futures with
//! [`MaybeSend`] lets each trait be defined once for both targets instead of
//! as a duplicated `#[cfg]` pair that default-target CI only half
//! type-checks.

/// Alias for `Send` on native targets; satisfied by every type on wasm32.
///
/// Never implement this manually — the blanket impl covers everything the
/// target allows.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// Alias for `Send` on native targets; satisfied by every type on wasm32.
///
/// Never implement this manually — the blanket impl covers everything the
/// target allows.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}
