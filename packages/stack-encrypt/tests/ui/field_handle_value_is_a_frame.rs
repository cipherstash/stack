//! A field handle's query holds its value until the term is derived, so it
//! takes only a value whose bytes are wiped: an `OwnedFrame`, a borrowed
//! `&OwnedFrame` or a `Frame`. A plain Rust value such as a `String` does
//! not compile. Write it into a frame first with `OwnedFrame::of`.
use stack_encrypt::dynamic::FieldHandle;

fn query(handle: FieldHandle<'_>) {
    let _ = handle.eq(String::from("ada@example.com"));
}

fn main() {}
