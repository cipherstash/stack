//! One Tokio runtime for the process, and the sync bridge over it.
//!
//! The engine's `Pending` is `IntoFuture`, so every operation is async even
//! though the tracer's surface is sync (decision 8: both eventually, over
//! one engine path; sync first). `block_on` is therefore the whole of the
//! sync path — there is no second engine entry for it, which is what keeps
//! principle G6 reachable when async arrives.
//!
//! **The GIL is released across the call.** The work inside is a ZeroKMS
//! HTTPS round trip, so holding it would stop every other Python thread for
//! the duration of a network call. A native shell is the one binding that
//! can simply let go of it: the WASI guest's `transport_send` is synchronous
//! from the guest's side and a JavaScript host cannot block its event loop
//! at all.

use std::sync::OnceLock;

use pyo3::prelude::*;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// The process's runtime, built on first use.
///
/// One for the process rather than one per handle: a `Runtime` owns a thread
/// pool, and a second handle should not mean a second pool. It is never shut
/// down, which is correct for an extension module — the interpreter outlives
/// it and a `Runtime` dropped while a task holds the GIL would deadlock.
fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("a Tokio runtime for the stackencrypt engine"))
}

/// Drive `future` to completion with the GIL released.
///
/// Bounded on `IntoFuture`, not `Future`: the engine's `Pending` is a value
/// that *becomes* a future when awaited (`IntoFuture`), so that the chain can
/// be built, zipped and inspected before anything runs. A plain `async fn`
/// such as `StackCipher::new()` is `IntoFuture` too, so one bound serves
/// both.
pub fn block_on<F>(py: Python<'_>, future: F) -> F::Output
where
    F: std::future::IntoFuture,
    F::IntoFuture: Send,
    F::Output: Send,
{
    // Converted BEFORE detaching, so the closure captures only the future and
    // `F` itself need not be `Send`.
    let future = future.into_future();
    py.detach(move || runtime().block_on(future))
}
