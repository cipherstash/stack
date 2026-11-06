//! The step loop: how a guest export that needs the network returns to its
//! host instead of blocking on it.
//!
//! An export that may reach ZeroKMS runs its work as a future, polled once
//! ([`start`]). Where the work sends an HTTP request ([`request`]), the
//! request is recorded and the future stays pending. The export then ends:
//! the future is kept in a table under a handle, and the host is handed the
//! handle and the requests it recorded ([`Step::NeedsIo`]). The host performs
//! them however it likes (a goroutine, `fetch`) and hands the responses back
//! ([`resume`]), in the order of the requests. The future is polled again,
//! and the loop repeats until it is done ([`Step::Done`]) or fails. A host
//! that gives up drops the operation ([`abort`]).
//!
//! The guest is never running while a request is in flight, so a host's
//! cancellation never interrupts it: an aborted operation is a future
//! dropped between two polls, and everything it held is wiped on drop.
//!
//! # Handles
//!
//! - A handle names one paused operation. It is issued when an operation
//!   first pauses, never before, so an export that completes in one poll
//!   costs no handle.
//! - Handles are issued in increasing order and never reused, so a stale
//!   [`resume`] can never reach another operation: it is an unknown handle.
//!   They are 64-bit so a long-lived instance never runs out: at a million
//!   pauses a second, that takes over half a million years.
//! - At most [`MAX_OPEN`] operations may be paused at once. One more is
//!   refused, and dropped, so a host that forgets to abort cannot grow the
//!   table without bound. The cap guards against a faulty host; a host
//!   with more concurrent callers than that bounds itself to it, so they
//!   wait rather than fail (the Go client does, in `Client.drive`).
//! - An unknown, finished or aborted handle is `STATUS_STATE`. It never
//!   panics.
//!
//! # Wakers
//!
//! The work may run requests through combinators that poll an inner future
//! again only once its waker has been woken (`FuturesOrdered`, `buffered`).
//! So each request stores the waker it was polled with, and [`resume`] wakes
//! it when its response arrives, before polling the operation again. The
//! operation itself is polled with a waker that does nothing: the loop polls
//! it on every step regardless.
//!
//! This module holds no encoding: the guest decides how a step's requests
//! and the host's responses cross the boundary.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroizing;

use crate::buffers;
use crate::last_error;

/// An operation's work: what an export would have run with `block_on`,
/// owning its inputs, with the export's output or status as its result.
pub type Operation = Pin<Box<dyn Future<Output = Result<Vec<u8>, u32>>>>;

/// The most operations that may be paused at once.
pub const MAX_OPEN: usize = 64;

/// One HTTP request an operation needs the host to perform.
///
/// The headers (in the [`crate::headers`] line format, a bearer token
/// among them) and the body (which can carry key-material contexts) are
/// wiped on drop.
#[derive(OpaqueDebug)]
#[non_exhaustive]
pub struct Request {
    /// The HTTP method.
    #[non_sensitive]
    pub method: &'static str,
    /// The URL.
    #[non_sensitive]
    pub url: String,
    /// The request headers.
    pub headers: Zeroizing<Vec<u8>>,
    /// The request body.
    pub body: Zeroizing<Vec<u8>>,
}

impl Request {
    /// A request.
    pub fn new(
        method: &'static str,
        url: String,
        headers: Zeroizing<Vec<u8>>,
        body: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            method,
            url,
            headers,
            body,
        }
    }
}

/// The host's answer to one [`Request`].
///
/// `Debug` shows the status alone: the body can carry wrapped key material
/// or a credential.
#[derive(OpaqueDebug)]
#[non_exhaustive]
pub struct Response {
    /// The HTTP status code, or negative for a transport-level failure —
    /// then `body` is the host's error text.
    #[non_sensitive]
    pub status: i32,
    /// The response headers, in the [`crate::headers`] line format.
    pub headers: Vec<u8>,
    /// The response body. Wiped on drop.
    pub body: Zeroizing<Vec<u8>>,
}

impl Response {
    /// A response.
    pub fn new(status: i32, headers: Vec<u8>, body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

/// What a step of an operation came to, when it did not fail.
#[derive(Debug)]
pub enum Step {
    /// The operation finished, with this output.
    Done(Vec<u8>),
    /// The operation is paused under `handle`, waiting for the host to
    /// perform `requests` and [`resume`] it with their responses, in order.
    NeedsIo {
        /// The paused operation.
        handle: u64,
        /// What it waits on.
        requests: Vec<Request>,
    },
}

/// A request made outside a step: the work was polled by something other
/// than [`start`] or [`resume`], so no host can be asked to perform it.
#[derive(Debug, thiserror::Error)]
#[error("an HTTP request was made outside a guest step")]
pub struct NotInStep;

/// One request of a paused operation, from the moment the work makes it to
/// the moment it reads the response.
#[derive(Default)]
struct Exchange {
    /// The request, until the step that made it hands it to the host.
    request: Option<Request>,
    /// The response, from [`resume`] until the work reads it.
    response: Option<Response>,
    /// The waker the request was last polled with.
    waker: Option<Waker>,
}

/// The requests of one operation.
#[derive(Default)]
struct Io {
    exchanges: RefCell<Vec<Exchange>>,
}

/// A paused operation.
struct Open {
    work: Operation,
    io: Rc<Io>,
    /// The exchanges whose requests the host was handed at the last step,
    /// in the order it was handed them: where [`resume`]'s responses go.
    awaiting: Vec<usize>,
}

thread_local! {
    /// The requests of the operation being polled, so [`request`] can record
    /// into them without the work knowing which operation it belongs to.
    static CURRENT: RefCell<Option<Rc<Io>>> = const { RefCell::new(None) };
    static OPEN: RefCell<BTreeMap<u64, Open>> = const { RefCell::new(BTreeMap::new()) };
    /// The next handle to issue. Zero is never issued.
    static NEXT: Cell<u64> = const { Cell::new(1) };
    /// A step's requests, encoded and registered for the host to take
    /// ([`take_pending`]).
    static PENDING: Cell<Option<(*mut u8, usize)>> = const { Cell::new(None) };
}

/// Send `request` through the host: record it for the step being polled,
/// and resolve to the host's response once [`resume`] delivers it.
///
/// The request is recorded on the first poll, which must happen inside a
/// step ([`start`] or [`resume`]); otherwise it resolves to [`NotInStep`].
pub fn request(request: Request) -> impl Future<Output = Result<Response, NotInStep>> {
    HostRequest::Unsent(Some(request))
}

enum HostRequest {
    Unsent(Option<Request>),
    Sent { io: Rc<Io>, index: usize },
    Finished,
}

impl Future for HostRequest {
    type Output = Result<Response, NotInStep>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this {
            HostRequest::Unsent(request) => {
                let Some(io) = CURRENT.with(|current| current.borrow().clone()) else {
                    *this = HostRequest::Finished;
                    return Poll::Ready(Err(NotInStep));
                };
                let index = {
                    let mut exchanges = io.exchanges.borrow_mut();
                    exchanges.push(Exchange {
                        request: request.take(),
                        response: None,
                        waker: Some(cx.waker().clone()),
                    });
                    exchanges.len() - 1
                };
                *this = HostRequest::Sent { io, index };
                Poll::Pending
            }
            HostRequest::Sent { io, index } => {
                let response = {
                    let mut exchanges = io.exchanges.borrow_mut();
                    let exchange = &mut exchanges[*index];
                    let response = exchange.response.take();
                    if response.is_none() {
                        exchange.waker = Some(cx.waker().clone());
                    }
                    response
                };
                match response {
                    Some(response) => {
                        *this = HostRequest::Finished;
                        Poll::Ready(Ok(response))
                    }
                    None => Poll::Pending,
                }
            }
            HostRequest::Finished => Poll::Ready(Err(NotInStep)),
        }
    }
}

/// Run an operation's first step.
///
/// # Errors
///
/// The operation's own failure, or `STATUS_STATE` when [`MAX_OPEN`]
/// operations are already paused (the operation is dropped), or
/// `STATUS_INTERNAL` when it paused without asking for anything.
pub fn start(work: Operation) -> Result<Step, u32> {
    clear_pending();
    step(None, work, Rc::default())
}

/// Hand a paused operation the responses to the requests its last step
/// asked for, in that order, and run its next step.
///
/// The handle is spent whatever the outcome: a paused operation comes back
/// under a new [`Step::NeedsIo`] with the same handle.
///
/// # Errors
///
/// `STATUS_STATE` for an unknown handle; `STATUS_ENCODING` when the number
/// of responses is not the number of requests (the operation is dropped);
/// otherwise as [`start`].
pub fn resume(handle: u64, responses: Vec<Response>) -> Result<Step, u32> {
    clear_pending();
    let Some(open) = OPEN.with(|open| open.borrow_mut().remove(&handle)) else {
        return Err(unknown_handle());
    };
    if responses.len() != open.awaiting.len() {
        drop(open);
        return Err(last_error::malformed(
            "the number of responses is not the number of requests",
        ));
    }
    {
        let mut exchanges = open.io.exchanges.borrow_mut();
        for (index, response) in open.awaiting.iter().zip(responses) {
            let exchange = &mut exchanges[*index];
            exchange.response = Some(response);
            if let Some(waker) = exchange.waker.take() {
                waker.wake();
            }
        }
    }
    step(Some(handle), open.work, open.io)
}

/// Drop a paused operation, wiping everything it held.
///
/// # Errors
///
/// `STATUS_STATE` for an unknown handle.
pub fn abort(handle: u64) -> Result<(), u32> {
    match OPEN.with(|open| open.borrow_mut().remove(&handle)) {
        Some(open) => {
            drop(open);
            Ok(())
        }
        None => Err(unknown_handle()),
    }
}

/// Drop every paused operation: what a guest's shutdown does before it
/// drops the state they share.
pub fn drop_all() {
    let open = OPEN.with(|open| core::mem::take(&mut *open.borrow_mut()));
    drop(open);
    clear_pending();
}

/// How many operations are paused.
pub fn open_count() -> usize {
    OPEN.with(|open| open.borrow().len())
}

/// Poll `work` once, as operation `handle` if it has one, and say what came
/// of it.
fn step(handle: Option<u64>, mut work: Operation, io: Rc<Io>) -> Result<Step, u32> {
    let previous = CURRENT.with(|current| current.replace(Some(io.clone())));
    let polled = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    CURRENT.with(|current| *current.borrow_mut() = previous);
    if let Poll::Ready(result) = polled {
        return result.map(Step::Done);
    }
    // Every request made since the last step, in the order made.
    let (awaiting, requests): (Vec<usize>, Vec<Request>) = {
        let mut exchanges = io.exchanges.borrow_mut();
        exchanges
            .iter_mut()
            .enumerate()
            .filter_map(|(index, exchange)| exchange.request.take().map(|r| (index, r)))
            .unzip()
    };
    if requests.is_empty() {
        // Nothing to wait for, so nothing would ever wake it.
        drop(work);
        return Err(last_error::internal(
            "an operation paused without asking the host for anything",
        ));
    }
    let handle = match handle {
        Some(handle) => handle,
        None => {
            if open_count() >= MAX_OPEN {
                drop(work);
                return Err(last_error::out_of_order(
                    "too many operations are paused: resume or abort one first",
                ));
            }
            issue()?
        }
    };
    OPEN.with(|open| {
        let _ = open
            .borrow_mut()
            .insert(handle, Open { work, io, awaiting });
    });
    Ok(Step::NeedsIo { handle, requests })
}

/// The next handle.
fn issue() -> Result<u64, u32> {
    NEXT.with(|next| {
        let handle = next.get();
        let following = handle
            .checked_add(1)
            .ok_or_else(|| last_error::out_of_order("this instance has issued every handle"))?;
        next.set(following);
        Ok(handle)
    })
}

fn unknown_handle() -> u32 {
    last_error::out_of_order("no paused operation has this handle")
}

/// Register a step's encoded requests for the host to take with
/// [`take_pending`], replacing (and wiping) any it did not take.
pub fn set_pending(bytes: Vec<u8>) {
    clear_pending();
    let len = bytes.len();
    let ptr = buffers::register(bytes);
    PENDING.with(|pending| pending.set(Some((ptr, len))));
}

/// Hand the registered requests over, emptying the slot: what the guest's
/// export returns to the host, which releases the buffer with `se_dealloc`.
pub fn take_pending() -> Option<(*mut u8, usize)> {
    PENDING.with(Cell::take)
}

/// Wipe and free registered requests the host never took.
fn clear_pending() {
    if let Some((ptr, len)) = PENDING.with(Cell::take) {
        // SAFETY: the pair is the one `buffers::register` returned in
        // `set_pending`, and nothing else holds it: the host is only given
        // it by `take_pending`, which empties the slot first.
        unsafe { buffers::dealloc(ptr, len) };
    }
}

/// Drop the slot without freeing, for a registry wipe about to free it.
pub(crate) fn forget_pending() {
    PENDING.with(|pending| pending.set(None));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{STATUS_ENCODING, STATUS_INTERNAL, STATUS_STATE};

    fn get(url: &str) -> Request {
        Request::new(
            "POST",
            url.to_owned(),
            Zeroizing::new(b"authorization: Bearer t\n".to_vec()),
            Zeroizing::new(b"{}".to_vec()),
        )
    }

    fn ok(body: &[u8]) -> Response {
        Response::new(200, Vec::new(), Zeroizing::new(body.to_vec()))
    }

    /// Starts a test from an empty table and slot, and leaves them empty:
    /// a recorded error or a paused operation is a registered buffer, which
    /// Miri reports as leaked if a test ends holding one.
    #[must_use]
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            drop_all();
            last_error::clear();
        }
    }

    fn reset() -> Reset {
        drop_all();
        last_error::clear();
        Reset
    }

    /// Work that makes `n` requests one after another and outputs their
    /// bodies joined.
    fn sequential(n: usize) -> Operation {
        Box::pin(async move {
            let mut out = Vec::new();
            for i in 0..n {
                let response = request(get(&format!("https://kms/{i}")))
                    .await
                    .map_err(|_| STATUS_INTERNAL)?;
                out.extend_from_slice(&response.body);
            }
            Ok(out)
        })
    }

    fn needs_io(step: Result<Step, u32>) -> (u64, Vec<Request>) {
        match step {
            Ok(Step::NeedsIo { handle, requests }) => (handle, requests),
            other => panic!("expected NeedsIo, got {other:?}"),
        }
    }

    #[test]
    fn work_that_needs_no_request_is_done_without_a_handle() {
        let _reset = reset();
        let step = start(Box::pin(async { Ok(b"out".to_vec()) })).unwrap();
        assert!(matches!(step, Step::Done(out) if out == b"out"));
        assert_eq!(open_count(), 0);
    }

    #[test]
    fn a_failure_is_the_status_and_holds_no_handle() {
        let _reset = reset();
        assert_eq!(
            start(Box::pin(async { Err(STATUS_ENCODING) })).unwrap_err(),
            STATUS_ENCODING
        );
        assert_eq!(open_count(), 0);
    }

    #[test]
    fn each_request_is_one_step_and_the_responses_reach_the_work() {
        let _reset = reset();
        let (handle, requests) = needs_io(start(sequential(2)));
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://kms/0");
        let (again, requests) = needs_io(resume(handle, vec![ok(b"a")]));
        assert_eq!(again, handle, "a paused operation keeps its handle");
        assert_eq!(requests[0].url, "https://kms/1");
        let done = resume(handle, vec![ok(b"b")]).unwrap();
        assert!(matches!(done, Step::Done(out) if out == b"ab"));
        assert_eq!(open_count(), 0);
        assert_eq!(
            resume(handle, vec![]).unwrap_err(),
            STATUS_STATE,
            "a finished handle is spent"
        );
    }

    /// `buffered` polls an inner future again only once it is woken: the
    /// stored waker is what keeps the operation from stalling after a
    /// response.
    #[test]
    fn a_combinator_that_waits_on_its_wakers_is_woken() {
        use futures::stream::{self, StreamExt};
        let _reset = reset();
        let work: Operation = Box::pin(async {
            let bodies: Vec<_> = stream::iter(0..3)
                .map(|i| request(get(&format!("https://kms/{i}"))))
                .buffered(1)
                .collect()
                .await;
            let mut out = Vec::new();
            for body in bodies {
                out.extend_from_slice(&body.map_err(|_| STATUS_INTERNAL)?.body);
            }
            Ok(out)
        });
        let (handle, _) = needs_io(start(work));
        needs_io(resume(handle, vec![ok(b"x")]));
        needs_io(resume(handle, vec![ok(b"y")]));
        let done = resume(handle, vec![ok(b"z")]).unwrap();
        assert!(matches!(done, Step::Done(out) if out == b"xyz"));
    }

    #[test]
    fn several_requests_in_one_step_take_their_responses_in_order() {
        use futures::future::join;
        let _reset = reset();
        let work: Operation = Box::pin(async {
            let (a, b) = join(request(get("https://kms/a")), request(get("https://kms/b"))).await;
            let mut out = a.map_err(|_| STATUS_INTERNAL)?.body.to_vec();
            out.extend_from_slice(&b.map_err(|_| STATUS_INTERNAL)?.body);
            Ok(out)
        });
        let (handle, requests) = needs_io(start(work));
        let urls: Vec<_> = requests.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(urls, ["https://kms/a", "https://kms/b"]);
        let done = resume(handle, vec![ok(b"1"), ok(b"2")]).unwrap();
        assert!(matches!(done, Step::Done(out) if out == b"12"));
    }

    #[test]
    fn handles_interleave_and_are_never_reused() {
        let _reset = reset();
        let (first, _) = needs_io(start(sequential(1)));
        let (second, _) = needs_io(start(sequential(1)));
        assert!(second > first);
        let done = resume(second, vec![ok(b"2")]).unwrap();
        assert!(matches!(done, Step::Done(out) if out == b"2"));
        let done = resume(first, vec![ok(b"1")]).unwrap();
        assert!(matches!(done, Step::Done(out) if out == b"1"));
        let (third, _) = needs_io(start(sequential(1)));
        assert!(third > second, "a spent handle is not issued again");
        abort(third).unwrap();
    }

    #[test]
    fn an_aborted_operation_is_dropped_and_its_handle_spent() {
        let _reset = reset();
        let dropped = Rc::new(Cell::new(false));
        struct Flag(Rc<Cell<bool>>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let flag = Flag(dropped.clone());
        let (handle, _) = needs_io(start(Box::pin(async move {
            let _flag = flag;
            request(get("https://kms"))
                .await
                .map_err(|_| STATUS_INTERNAL)?;
            Ok(Vec::new())
        })));
        assert!(!dropped.get());
        abort(handle).unwrap();
        assert!(dropped.get(), "aborting drops the work");
        assert_eq!(abort(handle).unwrap_err(), STATUS_STATE);
        assert_eq!(resume(handle, vec![ok(b"")]).unwrap_err(), STATUS_STATE);
    }

    #[test]
    fn the_wrong_number_of_responses_is_refused_and_drops_the_operation() {
        let _reset = reset();
        let (handle, _) = needs_io(start(sequential(1)));
        assert_eq!(resume(handle, vec![]).unwrap_err(), STATUS_ENCODING);
        assert_eq!(open_count(), 0);
    }

    #[test]
    fn no_more_than_max_open_operations_pause() {
        let _reset = reset();
        for _ in 0..MAX_OPEN {
            needs_io(start(sequential(1)));
        }
        assert_eq!(start(sequential(1)).unwrap_err(), STATUS_STATE);
        assert_eq!(open_count(), MAX_OPEN);
        // A step that completes needs no handle, so it still runs.
        assert!(matches!(
            start(Box::pin(async { Ok(Vec::new()) })),
            Ok(Step::Done(_))
        ));
        drop_all();
        assert_eq!(open_count(), 0);
    }

    #[test]
    fn work_that_pauses_without_a_request_is_an_internal_failure() {
        let _reset = reset();
        let work: Operation = Box::pin(futures::future::pending());
        assert_eq!(start(work).unwrap_err(), STATUS_INTERNAL);
        assert_eq!(open_count(), 0);
    }

    #[test]
    fn a_request_outside_a_step_says_so() {
        let mut work = Box::pin(request(get("https://kms")));
        let polled = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(polled, Poll::Ready(Err(NotInStep))));
    }

    /// A registry wipe frees the step's buffer with every other, so the slot
    /// must not go on naming it.
    #[test]
    fn a_registry_wipe_empties_the_slot() {
        let _reset = reset();
        set_pending(b"step".to_vec());
        buffers::wipe_all();
        assert!(take_pending().is_none());
    }

    #[test]
    fn pending_requests_are_handed_over_once_and_replaced_wiped() {
        let _reset = reset();
        set_pending(b"one".to_vec());
        set_pending(b"two".to_vec());
        let (ptr, len) = take_pending().unwrap();
        // SAFETY: registered above and handed over once.
        let bytes = unsafe { buffers::take(ptr, len) }.unwrap();
        assert_eq!(bytes, b"two");
        assert!(take_pending().is_none());
    }
}
