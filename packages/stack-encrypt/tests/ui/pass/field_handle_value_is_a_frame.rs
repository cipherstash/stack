//! The values a field handle's query does take: an owned frame, a borrowed
//! one, and a frame parsed from bytes the caller keeps.
use stack_encrypt::dynamic::frame::{Frame, OwnedFrame};
use stack_encrypt::dynamic::FieldHandle;

fn owned(handle: FieldHandle<'_>, value: OwnedFrame) {
    let _ = handle.eq(value);
}

fn borrowed(handle: FieldHandle<'_>, value: &OwnedFrame) {
    let _ = handle.eq(value);
}

fn parsed(handle: FieldHandle<'_>, bytes: &[u8]) {
    let _ = handle.eq(Frame::parse(bytes).unwrap());
}

fn main() {}
