use futures::{Stream, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// How many keys a batch derives between yields. A key costs tens of
/// microseconds in a wasm guest, so a chunk is a few milliseconds there and
/// far less natively. `stack-encrypt` has its own copy (in
/// `target::pending`, for a column's items), and the two are meant to stay
/// equal.
pub(crate) const YIELD_EVERY: usize = 64;

/// Yield to the async runtime once: wake this task and return pending, so
/// the runtime can run other work before it polls this one again. On tokio
/// that reschedules the task. In a wasm guest's step loop it hands control
/// back to the host, which cannot preempt the guest (see `stack-guest-abi`'s
/// step module).
pub(crate) fn yield_now() -> YieldNow {
    YieldNow(false)
}

/// The future [`yield_now`] returns. `stack-encrypt` has its own copy (in
/// `target::pending`), and the two are meant to stay equal.
pub(crate) struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Split `input` into chunks of `chunk_size`, and run `callback` on up to
/// `concurrent_futs` chunks at once. The stream gives each chunk with its
/// callback's output, in chunk order. It starts the next chunk's callback
/// only when it is polled again, so a caller that works through each output
/// before polling holds at most `concurrent_futs` outputs.
pub(crate) fn map_chunks_buffered<'a, T, F, C>(
    input: &'a [T],
    mut callback: C,
    chunk_size: usize,
    concurrent_futs: usize,
) -> impl Stream<Item = (&'a [T], F::Output)>
where
    F: Future,
    C: FnMut(&'a [T]) -> F,
{
    futures::stream::iter(input.chunks(chunk_size))
        .map(move |chunk| {
            let fut = callback(chunk);
            async move { (chunk, fut.await) }
        })
        .buffered(concurrent_futs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Collect the stream as `send_chunked` does, without keys: append each
    /// chunk's output in order, and stop at the first error.
    async fn map_async_chunked<'a, T, U, E, F, C>(
        input: &'a [T],
        callback: C,
        chunk_size: usize,
        concurrent_futs: usize,
    ) -> Result<Vec<U>, E>
    where
        F: Future<Output = Result<Vec<U>, E>>,
        C: FnMut(&'a [T]) -> F,
    {
        let mut stream = std::pin::pin!(map_chunks_buffered(
            input,
            callback,
            chunk_size,
            concurrent_futs
        ));
        let mut output = Vec::new();
        while let Some((_, result)) = stream.next().await {
            output.append(&mut result?);
        }
        Ok(output)
    }

    #[tokio::test]
    async fn each_output_comes_with_its_chunk() {
        let input = vec![1, 2, 3, 4, 5];
        let pairs: Vec<_> = map_chunks_buffered(&input, |x| async move { x.len() }, 2, 3)
            .collect()
            .await;
        assert_eq!(pairs, [(&[1, 2][..], 2), (&[3, 4][..], 2), (&[5][..], 1)]);
    }

    #[tokio::test]
    async fn test_keeps_the_same_order() {
        let input = vec![200, 100, 50, 25, 20, 15, 10, 5, 4, 3, 2, 1];

        let output = map_async_chunked(
            &input,
            |x| async {
                // Sleep for the chunk's own (descending) value so that a
                // regression to unordered buffering would reorder the output.
                tokio::time::sleep(Duration::from_millis(x[0])).await;
                Result::<_, ()>::Ok(x.to_vec())
            },
            2,
            10,
        )
        .await
        .unwrap();

        assert_eq!(input, output);
    }

    #[tokio::test]
    async fn test_a_failing_chunk_fails_the_whole_call() {
        let input = vec![1, 2, 3, 4, 5, 6];

        let result = map_async_chunked(
            &input,
            |chunk| async move {
                if chunk.contains(&4) {
                    Err(format!("chunk {chunk:?} failed"))
                } else {
                    Ok(chunk.to_vec())
                }
            },
            2,
            3,
        )
        .await;

        assert_eq!(result, Err("chunk [3, 4] failed".to_string()));
    }

    #[tokio::test]
    async fn test_works_when_chunks_dont_divide_nicely() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let output = map_async_chunked(&input, |x| async { Result::<_, ()>::Ok(x.to_vec()) }, 3, 1)
            .await
            .unwrap();

        assert_eq!(input, output);
    }
    #[test]
    fn concurrency_limit_bounds_chunks_and_drop_releases_them() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::task::{Context, Waker};

        struct InFlight(Arc<AtomicUsize>);
        impl Drop for InFlight {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let active = Arc::new(AtomicUsize::new(0));
        let chunks = Arc::new(Mutex::new(Vec::new()));
        let input: Vec<_> = (0..10).collect();
        let mut work = Box::pin(map_async_chunked(
            &input,
            |chunk| {
                let active = active.clone();
                let chunks = chunks.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _in_flight = InFlight(active);
                    chunks.lock().unwrap().push(chunk.to_vec());
                    std::future::pending::<Result<Vec<i32>, ()>>().await
                }
            },
            3,
            2,
        ));
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(active.load(Ordering::SeqCst), 2);
        assert_eq!(*chunks.lock().unwrap(), vec![vec![0, 1, 2], vec![3, 4, 5]]);
        drop(work);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_yield_wakes_itself_and_is_pending_once_then_ready() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};

        /// A waker that counts its wakes.
        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut yielded = yield_now();

        assert!(Pin::new(&mut yielded).poll(&mut cx).is_pending());
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "a yield that did not wake itself would never be polled again"
        );
        assert!(Pin::new(&mut yielded).poll(&mut cx).is_ready());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1, "it wakes itself once");
    }
}
