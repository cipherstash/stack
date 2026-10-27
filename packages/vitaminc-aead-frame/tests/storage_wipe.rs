//! Writing a blob must not free a block with the value still in it.
//!
//! The writer grows its buffer, formats a `Display` value, and hands back
//! a blob the caller drops. Each of those frees a block that held the
//! value. This test installs a global allocator that, while
//! armed, counts how many times a marker is still in a block as it is
//! freed. It lives in its own test binary so the allocator sees nothing but
//! these writes.
#![cfg(feature = "serde")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vitaminc_aead_frame::storage::{from_slice, to_vec};
use vitaminc_protected::Controlled;

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
    let (left, blob) = left_behind(|| to_vec(&map).expect("writes").risky_unwrap());
    assert!(blob.windows(MARKER.len()).any(|w| w == MARKER));
    assert_eq!(left, 0, "a freed block still held the value");

    // A value and a key written through `Display` are formatted straight
    // into the blob. The pairs are built before arming, so only the
    // writer's own blocks are inspected.
    struct Shown(String);
    impl serde::Serialize for Shown {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(&format_args!("{}", self.0))
        }
    }
    struct Entries(Vec<(Shown, Shown)>);
    impl serde::Serialize for Entries {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = s.serialize_map(Some(self.0.len()))?;
            for (key, value) in &self.0 {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }
    let shown = Entries(
        (0..64)
            .map(|i| (Shown(marked(i)), Shown(marked(i + 64))))
            .collect(),
    );
    let (left, blob) = left_behind(|| to_vec(&shown).expect("writes").risky_unwrap());
    assert!(blob.windows(MARKER.len()).any(|w| w == MARKER));
    assert_eq!(left, 0, "a displayed value was left in a freed block");

    // Integer keys are compared by value, a copy of each key, when the
    // writer checks its own blob and when the reader checks one. Keys whose
    // bytes are the marker show that copy is wiped.
    let base = u128::from_le_bytes(*MARKER);
    let integers: BTreeMap<u128, u8> = (0..64).map(|i| (base + (i << 120), 1)).collect();
    let (left, blob) = left_behind(|| to_vec(&integers).expect("writes").risky_unwrap());
    assert_eq!(left, 0, "an integer key's copy was left in a freed block");
    // What is read is the caller's, and kept past the armed read.
    let mut read = BTreeMap::<u128, u8>::new();
    let (left, _) = left_behind(|| {
        read = from_slice(&blob).expect("reads");
        Vec::new()
    });
    assert_eq!(read, integers);
    assert_eq!(
        left, 0,
        "reading left an integer key's copy in a freed block"
    );

    // The blob is wiped when it is dropped.
    let blob = to_vec(&map).expect("writes");
    let (left, _) = left_behind(|| {
        drop(blob);
        Vec::new()
    });
    assert_eq!(left, 0, "a dropped blob still held the value");

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
