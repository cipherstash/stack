//! [`Timestamp`]: a UTC instant that always encrypts.

use ::chrono::{DateTime, Utc};
use vitaminc_protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::plaintext::{depth, Encrypt, FixedType, Int, Logical, Physical, Sink, TimeUnit, Width};
use crate::typed::FromScalar;

/// A UTC instant that is never a leap second, so it can always be encrypted.
///
/// chrono represents a leap second as a `DateTime` whose nanoseconds run past
/// 999,999,999. That is a real instant with no count of seconds or
/// nanoseconds since the epoch, so it has no encoding, and encrypting a
/// `DateTime<Utc>` that holds one fails at runtime. A `Timestamp` refuses
/// the leap second when it is built instead, so a field of this type is
/// never refused when its struct is encrypted. Both encrypt to the same
/// leaf, so a `DateTime<Utc>` field can become a `Timestamp` without
/// changing its ciphertext.
///
/// ```
/// use chrono::{DateTime, NaiveDate};
/// use vitaminc_aead::{LeapSecond, Timestamp};
///
/// let instant = DateTime::from_timestamp(1_700_000_000, 0).expect("in range");
/// let ts = Timestamp::new(instant)?;
/// assert_eq!(ts.to_datetime(), instant);
///
/// let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
///     .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 1_500_000_000))
///     .expect("a leap second")
///     .and_utc();
/// assert!(Timestamp::new(leap).is_err());
/// # Ok::<(), LeapSecond>(())
/// ```
///
/// A `Timestamp` is plaintext, so it is handled as the data model's other
/// scalars are. It holds the instant as a count of seconds and of
/// nanoseconds, which it wipes when dropped; a `DateTime<Utc>` cannot be
/// wiped, because its fields are private. Equality is constant time (see
/// [`TimingSafeEq`](vitaminc_protected::TimingSafeEq)). It is not `Copy`
/// or `Clone`, so it is not copied without a trace, and it has no
/// ordering or hash, which would compare plaintext in variable time.
/// `Debug` is redacted. `Default` is the Unix epoch, as for
/// `DateTime<Utc>`, so a `#[aead(skip)]` or `#[aead(take)]` field can
/// change from one to the other.
#[derive(Default, OpaqueDebug, TimingSafeEq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch.
    secs: i64,
    /// Nanoseconds past `secs`, below one second.
    nanos: u32,
}

/// A leap second, which a [`Timestamp`] cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a leap second has no encoding")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
pub struct LeapSecond;

impl Timestamp {
    /// The instant, unless it is a leap second.
    ///
    /// # Errors
    ///
    /// [`LeapSecond`] if `instant` is a leap second.
    pub fn new(instant: DateTime<Utc>) -> Result<Self, LeapSecond> {
        let nanos = instant.timestamp_subsec_nanos();
        if nanos >= NANOS_PER_SECOND {
            return Err(LeapSecond);
        }
        Ok(Self {
            secs: instant.timestamp(),
            nanos,
        })
    }

    /// The instant, as a `DateTime<Utc>`. The copy is the caller's to
    /// look after: it cannot be wiped.
    pub fn to_datetime(&self) -> DateTime<Utc> {
        // A `Timestamp` is only built from a `DateTime<Utc>` that is not a
        // leap second, whose seconds and nanoseconds always make one again,
        // so the fallback is never taken. It is there so this cannot panic.
        DateTime::from_timestamp(self.secs, self.nanos).unwrap_or_default()
    }

    /// Nanoseconds since the epoch: the leaf a `DateTime<Utc>` encrypts to.
    fn count(&self) -> i128 {
        i128::from(self.secs) * i128::from(NANOS_PER_SECOND) + i128::from(self.nanos)
    }
}

const NANOS_PER_SECOND: u32 = 1_000_000_000;

impl TryFrom<DateTime<Utc>> for Timestamp {
    type Error = LeapSecond;

    fn try_from(instant: DateTime<Utc>) -> Result<Self, LeapSecond> {
        Self::new(instant)
    }
}

impl From<Timestamp> for DateTime<Utc> {
    fn from(ts: Timestamp) -> Self {
        ts.to_datetime()
    }
}

/// The same leaf as `DateTime<Utc>`: a timestamp in nanoseconds. A
/// `Timestamp` is never a leap second, so this never fails for its own
/// sake.
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

/// Any unit, as for `DateTime<Utc>`. A decoded count is never a leap second.
impl FromScalar for Timestamp {
    const EXPECTED: &'static str = "timestamp";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        DateTime::<Utc>::from_scalar(ty, value).and_then(|instant| Self::new(instant).ok())
    }
}

#[cfg(test)]
mod tests {
    use ::chrono::NaiveDate;

    use super::*;
    use crate::{plan, to_frame, EncryptError};
    use vitaminc_protected::Controlled;

    fn frame<P: Encrypt>(value: P) -> Vec<u8> {
        to_frame(value).expect("frames").risky_ref().clone()
    }

    fn leap() -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2016, 12, 31)
            .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 1_000_000_000))
            .expect("a leap second")
            .and_utc()
    }

    #[test]
    fn a_leap_second_is_refused_when_built() {
        assert_eq!(Timestamp::new(leap()).err(), Some(LeapSecond));
        assert_eq!(Timestamp::try_from(leap()).err(), Some(LeapSecond));
        assert_eq!(LeapSecond.to_string(), "a leap second has no encoding");

        let last = NaiveDate::from_ymd_opt(2016, 12, 31)
            .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 999_999_999))
            .expect("ok")
            .and_utc();
        let ts = Timestamp::new(last).expect("not a leap second");
        assert_eq!(ts.to_datetime(), last);
        assert_eq!(DateTime::<Utc>::from(ts), last);
    }

    /// Every instant a `Timestamp` can be built from comes back unchanged,
    /// so the fallback in `to_datetime` is never taken.
    #[test]
    fn every_instant_comes_back_as_it_went_in() {
        for instant in [
            DateTime::<Utc>::MIN_UTC,
            DateTime::<Utc>::MAX_UTC,
            DateTime::<Utc>::UNIX_EPOCH,
            DateTime::from_timestamp(-1, 999_999_999).expect("ok"),
            DateTime::from_timestamp(1_700_000_000, 123_456_789).expect("ok"),
        ] {
            let ts = Timestamp::new(instant).expect("not a leap second");
            assert_eq!(ts.to_datetime(), instant, "{instant}");
        }
        assert_eq!(
            Timestamp::default().to_datetime(),
            DateTime::<Utc>::UNIX_EPOCH
        );
    }

    /// Plaintext handling: constant-time equality, wiped by `zeroize`, and
    /// a redacted `Debug`.
    #[test]
    fn it_compares_in_constant_time_wipes_and_redacts() {
        let at = |secs, nanos| {
            Timestamp::new(DateTime::from_timestamp(secs, nanos).expect("ok")).expect("ok")
        };
        assert!(bool::from(at(5, 1).ts_eq(&at(5, 1))));
        assert!(at(5, 1) == at(5, 1));
        assert!(at(5, 1) != at(5, 2));
        assert!(at(5, 1) != at(6, 1));
        let mut ts = at(1_700_000_000, 7);
        ts.zeroize();
        assert!(ts == Timestamp::default());
        let shown = format!("{:?}", at(1_700_000_000, 7));
        assert!(!shown.contains("1700000000"), "{shown}");
    }

    /// A `Timestamp` gives the same leaf as the `DateTime` it was built
    /// from, owned or borrowed; the `DateTime` walk is what refuses a leap
    /// second, which is why the newtype exists.
    #[test]
    fn it_walks_as_the_datetime_it_holds() {
        for instant in [
            DateTime::from_timestamp(1, 5).expect("ok"),
            DateTime::from_timestamp(-1, 999_999_999).expect("ok"),
            DateTime::<Utc>::MIN_UTC,
            DateTime::<Utc>::MAX_UTC,
        ] {
            let ts = Timestamp::new(instant).expect("ok");
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
        assert_eq!(
            decoded.to_datetime(),
            DateTime::from_timestamp(1, 5).expect("ok")
        );
        assert!(Timestamp::from_scalar(None, Physical::Int(Int::I128(1))).is_none());

        assert!(matches!(
            plan::<_, (), _>(leap(), "aad"),
            Err(EncryptError::Source(_))
        ));
    }
}
