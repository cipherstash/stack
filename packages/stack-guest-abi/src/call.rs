//! What every export does around its body, in the part that is not wasm:
//! the last-error lifecycle ([`run`]) and the packed `u64` result
//! ([`pack_buffer`], [`pack_status`]).
//!
//! The wasm32 exports in [`abi`](crate::abi) are thin shims over these, so
//! the rules they hold — an export clears the last error when it starts and
//! again when it succeeds, a panic is an internal failure, a failure always
//! leaves an error recorded — are tested natively and under Miri, and the
//! leak tests of both guests drive [`run`] itself rather than a copy of it.
//!
//! The packing takes the pointer as a `u32` address: on wasm32 that is the
//! whole pointer. A native pointer does not fit, which is why the exports
//! themselves exist only on wasm32 (see the crate docs).

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::buffers;
use crate::last_error;

/// Run an export's body: clear the last error, run `f` (a panic is an
/// internal failure), and then clear the last error again if `f` succeeded,
/// or make sure one is recorded if it failed ([`last_error::ensure`]).
///
/// wasm32-wasip1 aborts on panic, so the catch is belt-and-braces for an
/// unwinding build; a native test unwinds, and so reaches it.
pub fn run<T>(f: impl FnOnce() -> Result<T, u32>) -> Result<T, u32> {
    last_error::clear();
    let result = catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(last_error::internal("a panic was caught")));
    match result {
        Ok(out) => {
            // An error recorded on the way to a success describes nothing
            // the host will ask about.
            last_error::clear();
            Ok(out)
        }
        Err(status) => {
            last_error::ensure(status);
            Err(status)
        }
    }
}

/// Pack a buffer result: the address in the high 32 bits, the length in
/// the low 32. A buffer's address is never zero, so a buffer result never
/// reads as a status.
pub fn pack_buffer(addr: u32, len: u32) -> u64 {
    (u64::from(addr) << 32) | u64::from(len)
}

/// Pack a status: the status in the low 32 bits, the high 32 zero.
pub fn pack_status(status: u32) -> u64 {
    u64::from(status)
}

/// The value `se_last_error` returns for the slot's contents: the packed
/// buffer of the recorded error, handed over and so emptied, or zero.
/// `addr` turns the registered pointer into its wasm32 address.
pub fn pack_last_error(addr: impl FnOnce(*mut u8) -> u32) -> u64 {
    match last_error::take_registered() {
        Some((ptr, len)) => pack_buffer(addr(ptr), len as u32),
        None => 0,
    }
}

/// What a host does after a failed call, for a native caller with no host:
/// call `se_last_error`'s packing ([`pack_last_error`]), decode the packed
/// value, and take the buffer it names out of the registry, as the host's
/// `se_dealloc` would release it. `None` when there was nothing to hand
/// over.
///
/// The guests' leak tests read every error through here, so what they
/// search is what the export would have handed the host.
pub fn take_last_error() -> Option<Vec<u8>> {
    let mut handed = None;
    let packed = pack_last_error(|ptr| {
        handed = Some(ptr);
        // Any non-zero address: the pointer itself is kept above, since a
        // native one does not fit in 32 bits.
        1
    });
    if packed >> 32 == 0 {
        return None;
    }
    let len = packed as u32 as usize;
    // SAFETY: `handed` is the registered pointer `pack_last_error` just
    // took out of the slot, and `len` its length as packed; nothing else
    // holds it.
    unsafe { buffers::take(handed?, len) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{STATUS_ENCODING, STATUS_INTERNAL};
    use vitaminc_aead_value::{transport as codec, FfiValue};

    /// A packed result, read the way the Go host reads it.
    #[derive(Debug, PartialEq)]
    enum Packed {
        Buffer { addr: u32, len: u32 },
        Status(u32),
    }

    fn unpack(packed: u64) -> Packed {
        let (high, low) = ((packed >> 32) as u32, packed as u32);
        if high == 0 {
            Packed::Status(low)
        } else {
            Packed::Buffer {
                addr: high,
                len: low,
            }
        }
    }

    /// The recorded error's code, handed over as the host would get it.
    fn last_code() -> Option<String> {
        let bytes = take_last_error()?;
        let value = codec::decode_value(&mut codec::Reader::new(&bytes)).expect("decodes");
        let FfiValue::Object(entries) = value else {
            return None;
        };
        entries.into_iter().find_map(|(key, value)| match value {
            FfiValue::String(code) if key == "code" => {
                String::from_utf8(code.risky_ref().to_vec()).ok()
            }
            _ => None,
        })
    }

    #[test]
    fn a_packed_result_reads_back_as_the_host_reads_it() {
        assert_eq!(
            unpack(pack_buffer(0x0010_0000, 7)),
            Packed::Buffer {
                addr: 0x0010_0000,
                len: 7
            }
        );
        assert_eq!(
            unpack(pack_buffer(u32::MAX, u32::MAX)),
            Packed::Buffer {
                addr: u32::MAX,
                len: u32::MAX
            }
        );
        assert_eq!(
            unpack(pack_status(STATUS_ENCODING)),
            Packed::Status(STATUS_ENCODING)
        );
    }

    #[test]
    fn a_failure_then_a_success_leaves_nothing_to_hand_over() {
        let _ = run(|| Err::<(), _>(last_error::malformed("first")));
        assert_eq!(run(|| Ok(())), Ok(()));
        assert_eq!(pack_last_error(|_| 1), 0);
    }

    #[test]
    fn an_error_recorded_on_the_way_to_a_success_is_cleared() {
        assert_eq!(
            run(|| {
                let _ = last_error::internal("recorded, then recovered from");
                Ok(())
            }),
            Ok(())
        );
        assert!(!last_error::is_set());
    }

    /// A call that fails without recording anything is described by its
    /// own status, never by an earlier call's error: [`run`] clears the
    /// slot when it starts.
    #[test]
    fn a_failure_never_reports_an_earlier_calls_error() {
        let _ = run(|| Err::<(), _>(last_error::malformed("marker-first-call")));
        assert_eq!(run(|| Err::<(), _>(STATUS_ENCODING)), Err(STATUS_ENCODING));
        let bytes = take_last_error().expect("recorded");
        assert!(
            !bytes
                .windows(b"marker-first-call".len())
                .any(|window| window == b"marker-first-call"),
            "the second call's error is its own"
        );
    }

    #[test]
    fn the_last_error_is_handed_over_once() {
        assert_eq!(run(|| Err::<(), _>(STATUS_ENCODING)), Err(STATUS_ENCODING));
        let mut handed = None;
        let first = pack_last_error(|ptr| {
            handed = Some(ptr);
            1
        });
        assert!(matches!(unpack(first), Packed::Buffer { addr: 1, len } if len > 0));
        assert_eq!(pack_last_error(|_| 1), 0, "the second call returns zero");
        // The host releases what it was handed, through the registry.
        let Packed::Buffer { len, .. } = unpack(first) else {
            unreachable!()
        };
        let ptr = handed.expect("a pointer was handed over");
        assert!(unsafe { buffers::take(ptr, len as usize) }.is_some());
        assert_eq!(take_last_error(), None);
    }

    #[test]
    fn a_panic_is_an_internal_failure() {
        let result = run(|| -> Result<(), u32> { panic!("marker-panic") });
        assert_eq!(result, Err(STATUS_INTERNAL));
        assert_eq!(last_code().as_deref(), Some("stack_guest_abi::internal"));
    }
}
