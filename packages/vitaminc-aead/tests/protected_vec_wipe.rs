//! A walked `Protected<Vec<T>>` must not free its buffer with the secrets
//! still in it.
//!
//! Elements of a `Vec<u64>` live in the vector's heap buffer, so taking
//! them out to walk them leaves their bytes behind. This test installs a
//! global allocator that, while armed, counts how many secret words are
//! still in each block as it is freed. It lives in its own test binary so
//! the allocator sees nothing but this walk.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vitaminc_aead::plaintext::{
    Encrypt, Error, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};
use vitaminc_protected::Protected;

const SECRET: u64 = 0x5EC2_E7C0_FFEE_D00D;

static ARMED: AtomicBool = AtomicBool::new(false);
static LEFT_IN_FREED_BLOCKS: AtomicUsize = AtomicUsize::new(0);

struct Inspecting;

// SAFETY: every call is forwarded to `System` unchanged. `dealloc` only
// reads the block it is about to free, which the caller still owns.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            let found = block
                .chunks_exact(8)
                .filter(|w| *w == SECRET.to_ne_bytes())
                .count();
            LEFT_IN_FREED_BLOCKS.fetch_add(found, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

#[derive(Debug)]
struct Stopped;

impl Error for Stopped {
    fn source(_: SourceError) -> Self {
        Stopped
    }
}

/// Keeps nothing, and fails at the element after the first `allow`.
struct Quiet {
    allow: usize,
}

impl Sink for Quiet {
    type Ok = ();
    type Error = Stopped;
    type Seq = Self;
    type Map = Self;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), Stopped> {
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Self, Stopped> {
        Ok(self)
    }

    fn map(self, _: Option<usize>) -> Result<Self, Stopped> {
        Ok(self)
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), Stopped> {
        Ok(())
    }
}

impl SeqSink for Quiet {
    type Ok = ();
    type Error = Stopped;
    type Element<'s> = Quiet;

    fn element(&mut self) -> Result<Quiet, Stopped> {
        if self.allow == 0 {
            return Err(Stopped);
        }
        self.allow -= 1;
        Ok(Quiet { allow: 0 })
    }

    fn end(self) -> Result<(), Stopped> {
        Ok(())
    }
}

impl MapSink for Quiet {
    type Ok = ();
    type Error = Stopped;
    type Entry<'s> = Quiet;

    fn entry(&mut self, _: &str) -> Result<Quiet, Stopped> {
        Ok(Quiet { allow: 0 })
    }

    fn end(self) -> Result<(), Stopped> {
        Ok(())
    }
}

/// Walk a protected vector of four secret words into `sink` and return
/// how many secret words were still in the blocks freed meanwhile.
fn left_behind(sink: Quiet) -> usize {
    let secrets = Protected::new(vec![SECRET; 4]);
    LEFT_IN_FREED_BLOCKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let _ = secrets.visit(sink);
    ARMED.store(false, Ordering::SeqCst);
    LEFT_IN_FREED_BLOCKS.load(Ordering::SeqCst)
}

// One test, so no other thread allocates while the allocator is armed.
#[test]
fn a_walked_protected_vec_frees_no_secret() {
    // The allocator does see the words when a block that holds them is
    // freed unwiped.
    let bare = vec![SECRET; 4];
    LEFT_IN_FREED_BLOCKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    drop(bare);
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(LEFT_IN_FREED_BLOCKS.load(Ordering::SeqCst), 4);

    // A walk that finishes, and one that stops after the first element.
    assert_eq!(left_behind(Quiet { allow: usize::MAX }), 0);
    assert_eq!(left_behind(Quiet { allow: 1 }), 0);
}
