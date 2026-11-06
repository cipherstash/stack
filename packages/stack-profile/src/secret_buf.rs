//! A byte buffer for secrets that is wiped on drop and whenever it grows.

use std::io::Read;

use zeroize::Zeroizing;

/// The capacity a [`SecretBuf`] starts with. Profile files are small (a token
/// file is well under 4 KiB), so most buffers never grow.
const INITIAL_CAPACITY: usize = 4096;

/// How much room [`SecretBuf::read_from`] makes for each read.
const READ_CHUNK: usize = 4096;

/// A byte buffer that is zeroized when dropped, including every allocation it
/// outgrows.
///
/// Wrapping a `Vec<u8>` in [`Zeroizing`] alone is not enough for a buffer
/// that grows: when a `Vec` reallocates, it frees the old allocation without
/// wiping it, leaving a copy of the bytes so far on the heap. `SecretBuf`
/// never lets its `Vec` reallocate itself. When it needs more room it
/// allocates a larger buffer, copies the contents across, and drops the old
/// one, which [`Zeroizing`] wipes. Spare capacity is wiped too, since
/// `Vec<u8>`'s `Zeroize` covers the whole allocation.
///
/// Writing to it ([`io::Write`](std::io::Write)) and reading into it
/// ([`read_from`](Self::read_from)) both write straight into the buffer, so
/// no intermediate copy of the bytes is left behind.
pub(crate) struct SecretBuf(Zeroizing<Vec<u8>>);

impl SecretBuf {
    pub(crate) fn new() -> Self {
        Self::with_capacity(INITIAL_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Read `reader` to its end.
    ///
    /// Unlike [`Read::read_to_end`], this does not depend on a correct size
    /// hint to avoid reallocating, and reads through no unwiped scratch
    /// buffer: a file whose metadata under-reports its length (as some
    /// network and FUSE filesystems do) still leaves no copy behind.
    pub(crate) fn read_from(mut reader: impl Read) -> std::io::Result<Self> {
        let mut buf = Self::new();
        loop {
            buf.reserve(READ_CHUNK)?;
            let filled = buf.0.len();
            // Within capacity, so this does not reallocate.
            buf.0.resize(filled + READ_CHUNK, 0);
            let result = reader.read(&mut buf.0[filled..]);
            buf.0.truncate(filled + *result.as_ref().unwrap_or(&0));
            match result {
                Ok(0) => return Ok(buf),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// The bytes held so far.
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

impl std::io::Write for SecretBuf {
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

    /// Yields its bytes a few at a time, with an `Interrupted` in between,
    /// the way a slow or signalled file read can.
    struct Trickle {
        bytes: Vec<u8>,
        pos: usize,
        interrupt_next: bool,
    }

    impl Read for Trickle {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.interrupt_next = !self.interrupt_next;
            if self.interrupt_next {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let n = out.len().min(3).min(self.bytes.len() - self.pos);
            out[..n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..=255).cycle().take(len).collect()
    }

    #[test]
    fn writes_hold_exactly_what_was_written() {
        let mut buf = SecretBuf::new();
        buf.write_all(b"hello, ").unwrap();
        buf.write_all(b"world").unwrap();
        assert_eq!(buf.as_bytes(), b"hello, world");
    }

    #[test]
    fn writes_grow_past_the_capacity_without_losing_bytes() {
        let mut buf = SecretBuf::with_capacity(4);
        let payload = payload(10_000);
        for chunk in payload.chunks(7) {
            buf.write_all(chunk).unwrap();
        }
        assert_eq!(buf.as_bytes(), payload.as_slice());
    }

    #[test]
    fn writes_match_serde_json_pretty_output() {
        let value = serde_json::json!({ "access_token": "secret", "expires_at": 1 });
        let mut buf = SecretBuf::with_capacity(1);
        serde_json::to_writer_pretty(&mut buf, &value).unwrap();
        assert_eq!(
            buf.as_bytes(),
            serde_json::to_string_pretty(&value).unwrap().as_bytes()
        );
    }

    #[test]
    fn read_from_reads_everything_across_many_growths() {
        let payload = payload(3 * INITIAL_CAPACITY + 17);
        let buf = SecretBuf::read_from(payload.as_slice()).unwrap();
        assert_eq!(buf.as_bytes(), payload.as_slice());
    }

    #[test]
    fn read_from_reads_an_empty_reader() {
        let buf = SecretBuf::read_from(&[][..]).unwrap();
        assert!(buf.as_bytes().is_empty());
    }

    #[test]
    fn read_from_retries_interrupted_and_short_reads() {
        let payload = payload(50);
        let reader = Trickle {
            bytes: payload.clone(),
            pos: 0,
            interrupt_next: false,
        };
        let buf = SecretBuf::read_from(reader).unwrap();
        assert_eq!(buf.as_bytes(), payload.as_slice());
    }

    #[test]
    fn read_from_returns_a_read_error() {
        let err = SecretBuf::read_from(Failing).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
