//! A path's key names can be customer data, so a path wipes them when it
//! drops, and a parse that refuses its text part way wipes the keys it has
//! read. Checked with an allocator that looks inside every block it frees.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use stack_encrypt_jsonpath::JsonPath;

/// A key name no other allocation in this test holds.
const MARK: &[u8] = b"kq7markzv";

/// Freed blocks that still held [`MARK`], while [`WATCHING`].
static FOUND: AtomicUsize = AtomicUsize::new(0);
static WATCHING: AtomicBool = AtomicBool::new(false);

struct Spy;

// SAFETY: every call is forwarded to `System`; `dealloc` only reads the
// block it is given before freeing it.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until
            // the `System.dealloc` below.
            let block = std::slice::from_raw_parts(ptr, layout.size());
            if block.windows(MARK.len()).any(|window| window == MARK) {
                let _ = FOUND.fetch_add(1, Ordering::SeqCst);
            }
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: Spy = Spy;

/// The freed blocks that held the mark while `run` ran.
fn leaked(run: impl FnOnce()) -> usize {
    FOUND.store(0, Ordering::SeqCst);
    WATCHING.store(true, Ordering::SeqCst);
    run();
    WATCHING.store(false, Ordering::SeqCst);
    FOUND.load(Ordering::SeqCst)
}

#[test]
fn a_path_and_a_refused_parse_leave_no_key_behind() {
    let mark = std::str::from_utf8(MARK).unwrap();
    let text = format!("$.{mark}[*].b");
    let quoted = format!("$[\"{mark}\"].b");
    let refused = format!("$.{mark}[x]");
    assert_eq!(
        leaked(|| {
            let path = JsonPath::parse(&text).unwrap();
            assert_eq!(path.segments().len(), 3);
            drop(path);
        }),
        0,
        "a plain key"
    );
    assert_eq!(
        leaked(|| drop(JsonPath::parse(&quoted).unwrap())),
        0,
        "a quoted key"
    );
    assert_eq!(
        leaked(|| assert!(JsonPath::parse(&refused).is_err())),
        0,
        "a refused parse"
    );
    // The control: the spy finds a key that is not wiped.
    assert_eq!(leaked(|| drop(mark.to_owned())), 1, "an unwiped copy");
}
