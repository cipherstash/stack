//! Writing a frame must not free a block with the value still in it.
//!
//! The transport serde writer and `vitaminc_aead::to_frame` share the frame
//! writer: it grows its buffer, checks a map's keys for a repeat, formats a
//! `Display` value, and hands back a frame the caller drops. Each of those
//! could free a block that held a key or a value. This test installs a
//! global allocator that, while armed, counts how many times a marker is
//! still in a block as it is freed. It lives in its own test binary so the
//! allocator sees nothing but these writes. `tests/storage_wipe.rs` does the
//! same for the storage profile.
#![cfg(feature = "serde")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use vitaminc_aead::to_frame;
use vitaminc_aead_frame::serde::to_vec;
use vitaminc_protected::Controlled;

const MARKER: &[u8; 16] = b"S3CR3T-M4RK3R-02";

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

fn holds_marker(frame: &[u8]) -> bool {
    frame.windows(MARKER.len()).any(|w| w == MARKER)
}

/// Run `write` armed, and return how many markers were left in the blocks
/// it freed. The value and the frame are built and dropped disarmed: they
/// are the caller's to wipe.
fn left_behind<T>(write: impl FnOnce() -> T) -> (usize, T) {
    LEFT_IN_FREED_BLOCKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let written = write();
    ARMED.store(false, Ordering::SeqCst);
    (LEFT_IN_FREED_BLOCKS.load(Ordering::SeqCst), written)
}

/// Written through `Display`, as a type whose `Serialize` calls
/// `collect_str` is.
struct Shown(String);

impl Serialize for Shown {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("{}", self.0))
    }
}

/// A map's entries in the order given, repeats and all.
struct Entries<K, V>(Vec<(K, V)>);

impl<K: Serialize, V: Serialize> Serialize for Entries<K, V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// One test, so nothing else allocates in this binary while it is armed.
#[test]
fn writing_frees_no_block_with_the_value_in_it() {
    // Keys and values that carry the marker, enough of them that the
    // buffer grows many times over, and that the map checks each key.
    let map: BTreeMap<String, String> = (0..64).map(|i| (marked(i), marked(i + 64))).collect();
    let (left, frame) = left_behind(|| to_vec(&map).expect("writes"));
    assert!(holds_marker(frame.risky_ref()));
    assert_eq!(left, 0, "a freed block still held a key or a value");

    // The same through the frame writer plaintext is sealed with.
    let (left, frame) = left_behind(|| to_frame(&map).expect("frames"));
    assert!(holds_marker(frame.risky_ref()));
    assert_eq!(left, 0, "to_frame left a key or a value in a freed block");

    // A value and a key written through `Display` are formatted into a
    // buffer that is wiped.
    let shown = Entries(
        (0..64)
            .map(|i| (Shown(marked(i)), Shown(marked(i + 64))))
            .collect(),
    );
    let (left, frame) = left_behind(|| to_vec(&shown).expect("writes"));
    assert!(holds_marker(frame.risky_ref()));
    assert_eq!(
        left, 0,
        "a displayed key or value was left in a freed block"
    );

    // A `Display` that writes the marker and then fails, as a value and
    // as a key, is refused, and what it wrote is wiped.
    struct FailsAfterMarker;
    impl core::fmt::Display for FailsAfterMarker {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(core::str::from_utf8(MARKER).expect("ASCII"))?;
            Err(core::fmt::Error)
        }
    }
    struct FailsShown;
    impl Serialize for FailsShown {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(&FailsAfterMarker)
        }
    }
    let (left, failed) = left_behind(|| to_vec(&FailsShown).is_err());
    assert!(failed, "a failing display as a value is refused");
    assert_eq!(left, 0, "a failing display left its value in a freed block");
    let as_key = Entries(vec![(FailsShown, 1u8)]);
    let (left, failed) = left_behind(|| to_vec(&as_key).is_err());
    assert!(failed, "a failing display as a key is refused");
    assert_eq!(left, 0, "a failing display left its key in a freed block");

    // A repeated key is refused, and what was written is wiped.
    let repeated = Entries(vec![(marked(1), marked(2)), (marked(1), marked(3))]);
    let (left, written) = left_behind(|| to_vec(&repeated).is_err());
    assert!(written, "a repeated key is refused");
    assert_eq!(left, 0, "a refused repeat left a key in a freed block");

    // The frame is wiped when it is dropped.
    let frame = to_vec(&map).expect("writes");
    let (left, ()) = left_behind(|| drop(frame));
    assert_eq!(left, 0, "a dropped frame still held the value");

    // A write that fails part way wipes what it had written.
    struct Fails<'a>(&'a BTreeMap<String, String>);
    impl Serialize for Fails<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(None)?;
            seq.serialize_element(self.0)?;
            Err(serde::ser::Error::custom("stop"))
        }
    }
    let (left, failed) = left_behind(|| to_vec(&Fails(&map)).is_err());
    assert!(failed);
    assert_eq!(left, 0, "a failed write left the value in a freed block");
}
