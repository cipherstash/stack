//! [`Timestamp`]: a UTC instant that is handled as plaintext.

use vitaminc_protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::plaintext::{
    depth, Encrypt, FixedType, Int, Logical, Physical, Scalar, Sink, TimeUnit, Width,
};
use crate::typed::FromScalar;

/// A UTC instant that is wiped when dropped.
///
/// A `jiff::Timestamp` is `Copy` and its fields are private, so it cannot
/// be wiped, and it compares and hashes in variable time. A `Timestamp`
/// holds the same instant as a count of seconds and of nanoseconds, which
/// it wipes when dropped. Both encrypt to the same leaf, so a
/// `jiff::Timestamp` field can become a `Timestamp` without changing its
/// ciphertext.
///
/// ```
/// use vitaminc_aead::Timestamp;
///
/// let instant = jiff::Timestamp::new(1_700_000_000, 0)?;
/// let ts = Timestamp::new(instant);
/// assert_eq!(ts.to_jiff(), instant);
/// # Ok::<(), jiff::Error>(())
/// ```
///
/// A `Timestamp` is plaintext, so it is handled as the data model's other
/// scalars are. Equality is constant time (see [`TimingSafeEq`]). It is
/// not `Copy` or `Clone`, so it is not copied without a trace, and it has
/// no ordering or hash, which would compare plaintext in variable time.
/// `Debug` is redacted. `Default` is the Unix epoch, as for
/// `jiff::Timestamp`, so a `#[aead(skip)]` or `#[aead(take)]` field can
/// change from one to the other.
#[derive(Default, OpaqueDebug, TimingSafeEq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(docsrs, doc(cfg(feature = "jiff")))]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch, rounded towards negative
    /// infinity.
    secs: i64,
    /// Nanoseconds past `secs`, below one second.
    nanos: u32,
}

impl Timestamp {
    /// The instant.
    pub fn new(instant: jiff::Timestamp) -> Self {
        let (secs, nanos) = (instant.as_second(), instant.subsec_nanosecond());
        // jiff gives the nanoseconds the sign of the seconds. Store them
        // as the nanoseconds past the second before instead. jiff's
        // seconds are far from `i64::MIN`, so the subtraction cannot
        // overflow.
        let (secs, nanos) = if nanos < 0 {
            (secs - 1, nanos + NANOS_PER_SECOND)
        } else {
            (secs, nanos)
        };
        Self {
            secs,
            nanos: nanos.unsigned_abs(),
        }
    }

    /// The instant, as a `jiff::Timestamp`. The copy is the caller's to
    /// look after: it cannot be wiped.
    pub fn to_jiff(&self) -> jiff::Timestamp {
        // A `Timestamp` is only built from a `jiff::Timestamp`, whose count
        // always makes one again, so the fallback is never taken. It is
        // there so this cannot panic.
        jiff::Timestamp::from_nanosecond(self.count()).unwrap_or_default()
    }

    /// Nanoseconds since the epoch: the leaf a `jiff::Timestamp` encrypts
    /// to.
    fn count(&self) -> i128 {
        i128::from(self.secs) * i128::from(NANOS_PER_SECOND) + i128::from(self.nanos)
    }
}

const NANOS_PER_SECOND: i32 = 1_000_000_000;

impl From<jiff::Timestamp> for Timestamp {
    fn from(instant: jiff::Timestamp) -> Self {
        Self::new(instant)
    }
}

impl From<Timestamp> for jiff::Timestamp {
    fn from(ts: Timestamp) -> Self {
        ts.to_jiff()
    }
}

/// The same leaf as `jiff::Timestamp`: a timestamp in nanoseconds.
impl Encrypt for Timestamp {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = <&Timestamp as Encrypt>::FIXED;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

impl Encrypt for &Timestamp {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> =
        FixedType::new(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128);
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(self.count())),
        )
    }
}

impl Scalar for Timestamp {}
impl Scalar for &Timestamp {}
const _: () = assert!(depth::is_scalar(<Timestamp as Encrypt>::DEPTH));

/// Any unit, as for `jiff::Timestamp`, and the same range: years -9999
/// to 9999.
impl FromScalar for Timestamp {
    const EXPECTED: &'static str = "timestamp";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        jiff::Timestamp::from_scalar(ty, value).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_frame;
    use vitaminc_protected::Controlled;

    fn frame<P: Encrypt>(value: P) -> Vec<u8> {
        to_frame(value).expect("frames").risky_ref().to_vec()
    }

    fn at(secs: i64, nanos: i32) -> jiff::Timestamp {
        jiff::Timestamp::new(secs, nanos).expect("instant")
    }

    /// Every instant comes back unchanged, so the fallback in `to_jiff` is
    /// never taken.
    #[test]
    fn every_instant_comes_back_as_it_went_in() {
        for instant in [
            jiff::Timestamp::MIN,
            jiff::Timestamp::MAX,
            jiff::Timestamp::UNIX_EPOCH,
            at(-1, -1),
            at(0, -1),
            at(-1, 0),
            at(1_700_000_000, 123_456_789),
        ] {
            let ts = Timestamp::new(instant);
            assert_eq!(ts.to_jiff(), instant, "{instant}");
            assert_eq!(jiff::Timestamp::from(Timestamp::from(instant)), instant);
            assert!(ts.nanos < 1_000_000_000, "{instant}");
        }
        assert_eq!(Timestamp::default().to_jiff(), jiff::Timestamp::UNIX_EPOCH);
    }

    /// Plaintext handling: constant-time equality, wiped by `zeroize`, and
    /// a redacted `Debug`.
    #[test]
    fn it_compares_in_constant_time_wipes_and_redacts() {
        let ts = |secs, nanos| Timestamp::new(at(secs, nanos));
        assert!(bool::from(ts(5, 1).ts_eq(&ts(5, 1))));
        assert!(ts(5, 1) == ts(5, 1));
        assert!(ts(5, 1) != ts(5, 2));
        assert!(ts(5, 1) != ts(6, 1));
        // The same instant, however jiff was given it.
        assert!(Timestamp::new(at(-1, -500_000_000)) == Timestamp::new(at(-2, 500_000_000)));
        let mut wiped = ts(1_700_000_000, 7);
        wiped.zeroize();
        assert!(wiped == Timestamp::default());
        let shown = format!("{:?}", ts(1_700_000_000, 7));
        assert!(!shown.contains("1700000000"), "{shown}");
    }

    /// A `Timestamp` gives the same leaf as the `jiff::Timestamp` it was
    /// built from, owned or borrowed.
    #[test]
    fn it_walks_as_the_instant_it_holds() {
        for instant in [
            at(1, 5),
            at(-1, -1),
            jiff::Timestamp::MIN,
            jiff::Timestamp::MAX,
        ] {
            let ts = Timestamp::new(instant);
            assert_eq!(frame(&ts), frame(instant), "{instant}");
            assert_eq!(frame(ts), frame(instant), "{instant}");
        }
        assert_eq!(<Timestamp as Encrypt>::DEPTH, Some(0));
        assert_eq!(<&Timestamp as Encrypt>::DEPTH, Some(0));

        let decoded = Timestamp::from_scalar(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(1_000_000_005)),
        )
        .expect("a timestamp");
        assert_eq!(decoded.to_jiff(), at(1, 5));
        assert!(Timestamp::from_scalar(None, Physical::Int(Int::I128(1))).is_none());
    }
}
