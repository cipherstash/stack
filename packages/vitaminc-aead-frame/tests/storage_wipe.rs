//! Writing a blob must not free a block with the value still in it.
//!
//! The writer grows its buffer, copies map keys to refuse a repeat, and
//! holds a map's key until its value is written. Each of those leaves a
//! freed block behind. This test installs a global allocator that, while
//! armed, counts how many times a marker is still in a block as it is
//! freed. It lives in its own test binary so the allocator sees nothing but
//! these writes.
#![cfg(feature = "serde")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vitaminc_aead_frame::storage::to_vec;

const MARKER: &[u8; 16] = b"S3CR3T-M4RK3R-01";

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
            let found = block.windows(MARKER.len()).filter(|w| w == MARKER).count();
            LEFT_IN_FREED_BLOCKS.fetch_add(found, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

fn marked(i: usize) -> String {
    format!("{}{i}", core::str::from_utf8(MARKER).expect("ASCII"))
}

/// Run `write` armed, and return how many markers were left in the blocks
/// it freed. The value and the blob are built and dropped disarmed: they
/// are the caller's to wipe.
fn left_behind(write: impl FnOnce() -> Vec<u8>) -> (usize, Vec<u8>) {
    LEFT_IN_FREED_BLOCKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let blob = write();
    ARMED.store(false, Ordering::SeqCst);
    (LEFT_IN_FREED_BLOCKS.load(Ordering::SeqCst), blob)
}

/// One test, so nothing else allocates in this binary while it is armed.
#[test]
fn writing_frees_no_block_with_the_value_in_it() {
    // Keys and values that carry the marker, enough of them that the
    // buffer grows many times over.
    let map: BTreeMap<String, Option<String>> =
        (0..64).map(|i| (marked(i), Some(marked(i + 64)))).collect();
    let (left, blob) = left_behind(|| to_vec(&map).expect("writes"));
    assert!(blob.windows(MARKER.len()).any(|w| w == MARKER));
    assert_eq!(left, 0, "a freed block still held the value");

    // A write that fails part way wipes what it had written.
    struct Fails<'a>(&'a BTreeMap<String, Option<String>>);
    impl serde::Serialize for Fails<'_> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut seq = s.serialize_seq(None)?;
            seq.serialize_element(self.0)?;
            Err(serde::ser::Error::custom("stop"))
        }
    }
    let (left, _) = left_behind(|| {
        assert!(to_vec(&Fails(&map)).is_err());
        Vec::new()
    });
    assert_eq!(left, 0, "a failed write left the value in a freed block");
}
