//! Reading the `(ptr, len)` pairs a host hands an export, on every target.
//!
//! A guest export receives its inputs as pointer/length pairs into its own
//! linear memory. [`GuestMemory`] is the range of addresses such a pair must
//! fall in, and its methods are the only place a pair becomes a slice:
//! [`GuestMemory::input`] validates and borrows, and
//! [`GuestMemory::take_plaintext`] copies and wipes. [`wipe_input`] zeroes a
//! validated range in place.
//!
//! On wasm32 the range is the whole of linear memory,
//! [`GuestMemory::linear`], and the `abi` module's `input` and
//! `take_plaintext` use it. This module has no wasm in it otherwise, so it
//! builds natively and runs under Miri (`miri:stack-guest-abi`), where a
//! test names the range with [`GuestMemory::spanning`] over a buffer it
//! owns. A validation that let a bad pair through would then build a slice
//! past that buffer, which Miri reports as undefined behaviour.

use vitaminc_protected::Protected;
use zeroize::Zeroize;

use crate::last_error;

/// The addresses a host-supplied pointer/length pair may name: a half-open
/// range `start..end`.
///
/// It holds addresses, not a borrow. A pair it admits can still name the
/// wrong bytes: the host owns its pointers, and the caller of
/// [`input`](Self::input) promises the range is a live host buffer. What
/// the check guarantees is that no slice is built outside the range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemory {
    start: usize,
    /// `u64`, not `usize`: on wasm32 a full 4 GiB memory (65536 pages) ends
    /// one past `u32::MAX`.
    end: u64,
}

impl GuestMemory {
    /// The whole of this instance's linear memory, at its current size.
    ///
    /// Read the size again for each call: memory grows, never shrinks, so a
    /// value read earlier only under-admits.
    #[cfg(target_arch = "wasm32")]
    pub fn linear() -> Self {
        Self {
            start: 0,
            end: core::arch::wasm32::memory_size::<0>() as u64 * 65536,
        }
    }

    /// The addresses of `region`, and no others.
    ///
    /// This keeps no borrow of `region`: the caller may write to it, or
    /// free it, afterwards. A pair admitted against a freed region is the
    /// caller's broken promise, as with any pair (see
    /// [`input`](Self::input)).
    pub fn spanning(region: &[u8]) -> Self {
        let start = region.as_ptr().addr();
        Self {
            start,
            end: start as u64 + region.len() as u64,
        }
    }

    /// Whether `addr..addr + len` lies inside this range, with `len` no
    /// more than `isize::MAX` (the limit on any slice) and the end not
    /// overflowing the address space.
    fn admits(&self, addr: usize, len: usize) -> bool {
        if len > isize::MAX as usize || addr < self.start {
            return false;
        }
        match addr.checked_add(len) {
            Some(end) => end as u64 <= self.end,
            None => false,
        }
    }

    /// Borrow a host-supplied `(ptr, len)` pair, validating before any
    /// slice exists.
    ///
    /// A zero length is the empty slice, whatever `ptr` is. Otherwise a
    /// null `ptr` is refused (treating it as empty would silently drop
    /// whatever bytes the host meant to pass), and so is a range that does
    /// not lie inside this memory. A refused pair records a malformed-input
    /// error and returns its status, `STATUS_ENCODING`.
    ///
    /// # Safety
    ///
    /// The bounds check keeps the read inside this memory. It cannot see
    /// who owns the range or for how long, and that is what the caller
    /// promises: `ptr`/`len` must name a buffer the host wrote and still
    /// owns, and that buffer must stay allocated and unwritten for the
    /// whole of `'a`. In practice the borrow ends before the export returns
    /// and before any wipe of an overlapping range ([`wipe_input`],
    /// [`take_plaintext`](Self::take_plaintext)). The lifetime is otherwise
    /// unconstrained, so a caller choosing `'static` over a range it is
    /// about to free would read freed memory: that is the promise, not a
    /// property this function can check.
    pub unsafe fn input<'a>(&self, ptr: *const u8, len: u32) -> Result<&'a [u8], u32> {
        let len = len as usize;
        if len == 0 {
            return Ok(&[]);
        }
        if ptr.is_null() || !self.admits(ptr.addr(), len) {
            return Err(last_error::malformed(
                "a pointer/length pair is outside guest memory",
            ));
        }
        // SAFETY: `ptr` is non-null and the range is inside this memory and
        // no longer than `isize::MAX`. Every byte of it is initialized: wasm
        // linear memory is (fresh pages are zero), and so is a `&[u8]` that
        // `spanning` was built over. That the range stays allocated and
        // unwritten for `'a` is the caller's contract, above.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    /// Take a plaintext input out of the host's buffer and wipe the buffer.
    ///
    /// An export that holds its decoded value across a host round trip
    /// would otherwise keep the borrow of the host buffer alive for the
    /// whole call. Copying into a `Protected` first lets the original be
    /// wiped at once: the plaintext then exists for the duration of the call
    /// and no longer, instead of sitting in linear memory until the host
    /// gets round to `se_dealloc`.
    ///
    /// Call it before any other buffer is borrowed, deliberately. The wipe
    /// writes through `&mut`, so no other `&[u8]` into this memory may be
    /// live, and a host that aliases its value range onto another argument
    /// therefore reads zeros there, which that argument's parser rejects.
    ///
    /// # Safety
    ///
    /// `ptr`/`len` must name a host buffer the caller is done with, with no
    /// borrow of any part of it live; it is zeroed before this returns.
    pub unsafe fn take_plaintext(&self, ptr: *mut u8, len: u32) -> Result<Protected<Vec<u8>>, u32> {
        // SAFETY: the borrow lives only for the copy on this line, over a
        // buffer the caller has promised is the host's and live.
        let taken = Protected::new(unsafe { self.input(ptr, len)? }.to_vec());
        // SAFETY: the range passed `input` just above, and the borrow it
        // returned ended with the copy.
        unsafe { wipe_input(ptr, len) };
        Ok(taken)
    }
}

/// Zeroize a validated input range in place, without freeing it: the host
/// still owns the buffer and releases it with `se_dealloc` after the call.
/// A null pointer or a zero length is a no-op.
///
/// # Safety
///
/// The range must have passed [`GuestMemory::input`], name a buffer that is
/// still live, and have no borrow of any part of it live.
pub unsafe fn wipe_input(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: the caller's contract: a validated, live range with no
    // outstanding borrow, so a unique borrow over it is sound.
    unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) }.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::STATUS_ENCODING;

    /// A 16-byte host buffer holding `0..16`, and the memory spanning it.
    fn host_buffer() -> (Vec<u8>, GuestMemory) {
        let buf: Vec<u8> = (0..16).collect();
        let memory = GuestMemory::spanning(&buf);
        (buf, memory)
    }

    /// Releases the last error a refusal recorded when the test ends. The
    /// error is a registered buffer, so a test that left it would leak it,
    /// and Miri fails a run that leaks.
    pub(super) struct ReleaseLastError;

    impl Drop for ReleaseLastError {
        fn drop(&mut self) {
            crate::last_error::clear();
        }
    }

    #[test]
    fn a_pair_inside_memory_borrows_exactly_its_bytes() {
        let _release = ReleaseLastError;
        let (buf, memory) = host_buffer();
        // SAFETY: `buf` is live and unwritten while the borrow is.
        let bytes = unsafe { memory.input(buf.as_ptr().wrapping_add(4), 8) }.unwrap();
        assert_eq!(bytes, &buf[4..12]);
    }

    #[test]
    fn the_whole_buffer_is_admitted_and_one_byte_more_is_not() {
        let _release = ReleaseLastError;
        let (buf, memory) = host_buffer();
        // SAFETY: as above.
        let whole = unsafe { memory.input(buf.as_ptr(), 16) }.unwrap();
        assert_eq!(whole, &buf[..]);
        // The last byte, then one past it.
        let last = buf.as_ptr().wrapping_add(15);
        assert_eq!(unsafe { memory.input(last, 1) }.unwrap(), &[15]);
        assert_eq!(unsafe { memory.input(last, 2) }, Err(STATUS_ENCODING));
    }

    #[test]
    fn a_range_running_past_the_end_is_refused() {
        let _release = ReleaseLastError;
        let (buf, memory) = host_buffer();
        let ptr = buf.as_ptr().wrapping_add(8);
        // SAFETY: refused before any slice is built; that is the property.
        assert_eq!(unsafe { memory.input(ptr, 9) }, Err(STATUS_ENCODING));
        // A pointer past the end with any length.
        let past = buf.as_ptr().wrapping_add(16);
        assert_eq!(unsafe { memory.input(past, 1) }, Err(STATUS_ENCODING));
    }

    #[test]
    fn a_range_starting_before_memory_is_refused() {
        let _release = ReleaseLastError;
        let buf: Vec<u8> = (0..16).collect();
        let memory = GuestMemory::spanning(&buf[4..]);
        // SAFETY: refused before any slice is built.
        assert_eq!(
            unsafe { memory.input(buf.as_ptr(), 4) },
            Err(STATUS_ENCODING)
        );
    }

    #[test]
    fn null_with_a_length_is_refused_and_any_zero_length_is_empty() {
        let _release = ReleaseLastError;
        let (_buf, memory) = host_buffer();
        // SAFETY: refused, or empty, before any slice over `ptr` is built.
        assert_eq!(
            unsafe { memory.input(std::ptr::null(), 1) },
            Err(STATUS_ENCODING)
        );
        assert_eq!(unsafe { memory.input(std::ptr::null(), 0) }, Ok(&[][..]));
        // A zero length is never dereferenced, so even an address outside
        // memory, with no provenance at all, is the empty slice.
        let nowhere = std::ptr::without_provenance::<u8>(0x10);
        assert_eq!(unsafe { memory.input(nowhere, 0) }, Ok(&[][..]));
    }

    #[test]
    fn a_range_that_overflows_the_address_space_is_refused() {
        let _release = ReleaseLastError;
        // A memory that runs to the top of the address space, and a
        // pointer whose end wraps past it.
        let memory = GuestMemory {
            start: 0,
            end: u64::MAX,
        };
        let near_top = std::ptr::without_provenance::<u8>(usize::MAX - 2);
        // SAFETY: refused before any slice is built.
        assert_eq!(unsafe { memory.input(near_top, 8) }, Err(STATUS_ENCODING));
    }

    #[test]
    fn a_length_over_isize_max_is_never_admitted() {
        let _release = ReleaseLastError;
        // Unreachable through a `u32` length on a 64-bit host, reachable on
        // wasm32, where `isize::MAX` is `i32::MAX`: checked on `admits`.
        let memory = GuestMemory {
            start: 0,
            end: u64::MAX,
        };
        assert!(memory.admits(1, isize::MAX as usize - 1));
        assert!(!memory.admits(1, isize::MAX as usize + 1));
    }

    #[test]
    fn a_refused_pair_records_a_malformed_input_error() {
        let _release = ReleaseLastError;
        let (_buf, memory) = host_buffer();
        crate::last_error::clear();
        // SAFETY: refused before any slice is built.
        let _ = unsafe { memory.input(std::ptr::null(), 4) };
        let recorded = crate::last_error::take().expect("an error is recorded");
        let value = crate::value::HostValue::decode(&recorded).expect("decodes");
        assert_eq!(
            value.get("code").and_then(|code| code.as_text()),
            Some("stack_guest_abi::malformed_input")
        );
    }

    #[test]
    fn take_plaintext_copies_then_wipes_the_host_buffer() {
        let _release = ReleaseLastError;
        let (mut buf, memory) = host_buffer();
        let ptr = buf.as_mut_ptr().wrapping_add(2);
        // SAFETY: `buf` is live, and nothing borrows it during the call.
        let taken = unsafe { memory.take_plaintext(ptr, 4) }.unwrap();
        use vitaminc_protected::Controlled as _;
        assert_eq!(taken.risky_unwrap(), vec![2, 3, 4, 5]);
        assert_eq!(&buf[..8], &[0, 1, 0, 0, 0, 0, 6, 7]);
    }

    #[test]
    fn take_plaintext_of_a_refused_pair_wipes_nothing() {
        let _release = ReleaseLastError;
        let (mut buf, memory) = host_buffer();
        let ptr = buf.as_mut_ptr().wrapping_add(12);
        // SAFETY: refused before any slice is built or written.
        assert_eq!(
            unsafe { memory.take_plaintext(ptr, 8) }.err(),
            Some(STATUS_ENCODING)
        );
        assert_eq!(buf, (0..16).collect::<Vec<u8>>());
    }

    /// What an export taking two plaintexts and a third input does when the
    /// host passes the same range for all three: each take wipes before the
    /// next borrow, so the later reads see zeros, and no borrow overlaps a
    /// write. Miri checks that last part.
    #[test]
    fn aliased_ranges_read_zeros_after_a_take_without_overlapping_borrows() {
        let _release = ReleaseLastError;
        let (mut buf, memory) = host_buffer();
        let ptr = buf.as_mut_ptr();
        use vitaminc_protected::Controlled as _;
        // SAFETY: each borrow ends before the next call writes.
        let first = unsafe { memory.take_plaintext(ptr, 8) }.unwrap();
        let second = unsafe { memory.take_plaintext(ptr.wrapping_add(4), 8) }.unwrap();
        let third = unsafe { memory.input(ptr, 16) }.unwrap().to_vec();
        assert_eq!(first.risky_unwrap(), (0..8).collect::<Vec<u8>>());
        assert_eq!(second.risky_unwrap(), vec![0, 0, 0, 0, 8, 9, 10, 11]);
        assert_eq!(&third[..12], &[0; 12]);
        assert_eq!(&third[12..], &[12, 13, 14, 15]);
    }

    #[test]
    fn wipe_input_of_null_or_empty_is_a_no_op() {
        let _release = ReleaseLastError;
        // SAFETY: neither is dereferenced.
        unsafe { wipe_input(std::ptr::null_mut(), 4) };
        unsafe { wipe_input(std::ptr::without_provenance_mut(0x10), 0) };
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            // Miri interprets every case, so it runs fewer.
            cases: if cfg!(miri) { 32 } else { 256 },
            // No regression file: the test runs under Miri's isolation.
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// `admits` is exactly "inside the range, slice-sized, no wrap".
        #[test]
        fn admits_is_the_bounds_rule(
            start in 0usize..1 << 20,
            size in 0u64..1 << 20,
            addr in 0usize..1 << 21,
            len in 0usize..1 << 21,
        ) {
            let memory = GuestMemory { start, end: start as u64 + size };
            let inside = addr >= start && (addr + len) as u64 <= start as u64 + size;
            prop_assert_eq!(memory.admits(addr, len), inside);
        }

        /// Every admitted pair over a real buffer borrows the bytes at its
        /// offset, and every refused one builds no slice. Run under Miri
        /// too, where a wrong answer is undefined behaviour.
        #[test]
        fn input_over_a_buffer_reads_only_inside_it(
            size in 1usize..32,
            offset in 0usize..40,
            len in 1u32..40,
        ) {
            let _release = super::tests::ReleaseLastError;
            let buf: Vec<u8> = (0..size as u8).collect();
            let memory = GuestMemory::spanning(&buf);
            let ptr = buf.as_ptr().wrapping_add(offset);
            // SAFETY: `buf` is live and unwritten while the borrow is.
            let got = unsafe { memory.input(ptr, len) };
            let end = offset + len as usize;
            if end <= size {
                prop_assert_eq!(got, Ok(&buf[offset..end]));
            } else {
                prop_assert_eq!(got, Err(crate::status::STATUS_ENCODING));
            }
        }
    }
}
