//! A byte buffer for serialising secrets, wiped on drop and on growth.

use zeroize::Zeroizing;

/// The capacity a [`ZeroizingWriter`] starts with. Profile files are small
/// (a token file is well under 4 KiB), so most writes never grow the buffer.
const INITIAL_CAPACITY: usize = 4096;

/// An [`io::Write`](std::io::Write) sink that keeps everything written to it
/// in a buffer that is zeroized when dropped.
///
/// Wrapping a `Vec<u8>` in [`Zeroizing`] alone is not enough for a buffer
/// that grows: when a `Vec` reallocates, it frees the old allocation without
/// wiping it, leaving a copy of the bytes written so far on the heap. This
/// writer never lets the `Vec` reallocate itself. When more room is needed it
/// allocates a larger buffer, copies the contents across, and drops the old
/// one, which [`Zeroizing`] wipes.
pub(crate) struct ZeroizingWriter(Zeroizing<Vec<u8>>);

impl ZeroizingWriter {
    pub(crate) fn new() -> Self {
        Self::with_capacity(INITIAL_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// The bytes written so far.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Make room for `additional` more bytes without letting the `Vec`
    /// reallocate in place.
    fn reserve(&mut self, additional: usize) -> std::io::Result<()> {
        let needed = self
            .0
            .len()
            .checked_add(additional)
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        if needed <= self.0.capacity() {
            return Ok(());
        }
        let capacity = needed.max(self.0.capacity().saturating_mul(2));
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(&self.0);
        // The old buffer is dropped here, and `Zeroizing` wipes it.
        self.0 = grown;
        Ok(())
    }
}

impl std::io::Write for ZeroizingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.reserve(buf.len())?;
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn it_holds_exactly_what_was_written() {
        let mut writer = ZeroizingWriter::new();
        writer.write_all(b"hello, ").unwrap();
        writer.write_all(b"world").unwrap();
        assert_eq!(writer.as_bytes(), b"hello, world");
    }

    #[test]
    fn it_grows_past_its_capacity_without_losing_bytes() {
        let mut writer = ZeroizingWriter::with_capacity(4);
        let payload: Vec<u8> = (0..=255).cycle().take(10_000).collect();
        for chunk in payload.chunks(7) {
            writer.write_all(chunk).unwrap();
        }
        assert_eq!(writer.as_bytes(), payload.as_slice());
    }

    #[test]
    fn it_never_lets_the_vec_reallocate_itself() {
        // Growth must go through `reserve`, which replaces the buffer, so the
        // `Vec` is always written within its existing capacity. If a write
        // reallocated in place, the capacity would change between `reserve`
        // and the write; asserting that `reserve` always leaves enough room
        // pins the invariant.
        let mut writer = ZeroizingWriter::with_capacity(1);
        for len in [1, 2, 3, 100, 1, 5_000] {
            writer.reserve(len).unwrap();
            let capacity = writer.0.capacity();
            writer.write_all(&vec![0xAB; len]).unwrap();
            assert_eq!(
                writer.0.capacity(),
                capacity,
                "a write after reserve must not reallocate"
            );
        }
    }

    #[test]
    fn it_matches_serde_json_pretty_output() {
        let value = serde_json::json!({ "access_token": "secret", "expires_at": 1 });
        let mut writer = ZeroizingWriter::with_capacity(1);
        serde_json::to_writer_pretty(&mut writer, &value).unwrap();
        assert_eq!(
            writer.as_bytes(),
            serde_json::to_string_pretty(&value).unwrap().as_bytes()
        );
    }
}
