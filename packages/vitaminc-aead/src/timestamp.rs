//! [`Timestamp`]: a UTC instant that always encrypts.

use ::chrono::{DateTime, Utc};
use vitaminc_protected::OpaqueDebug;

use crate::plaintext::{depth, Encrypt, Logical, Physical, Sink};
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
/// assert_eq!(ts.into_inner(), instant);
///
/// let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
///     .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 1_500_000_000))
///     .expect("a leap second")
///     .and_utc();
/// assert_eq!(Timestamp::new(leap), Err(LeapSecond));
/// # Ok::<(), LeapSecond>(())
/// ```
///
/// `Debug` is redacted, as for every plaintext scalar.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, OpaqueDebug)]
pub struct Timestamp(DateTime<Utc>);

/// A leap second, which a [`Timestamp`] cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a leap second has no encoding")]
pub struct LeapSecond;

impl Timestamp {
    /// The instant, unless it is a leap second.
    ///
    /// # Errors
    ///
    /// [`LeapSecond`] if `instant` is a leap second.
    pub fn new(instant: DateTime<Utc>) -> Result<Self, LeapSecond> {
        if instant.timestamp_subsec_nanos() >= 1_000_000_000 {
            return Err(LeapSecond);
        }
        Ok(Self(instant))
    }

    /// The instant, borrowed.
    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }

    /// The instant.
    pub fn into_inner(self) -> DateTime<Utc> {
        self.0
    }
}

impl TryFrom<DateTime<Utc>> for Timestamp {
    type Error = LeapSecond;

    fn try_from(instant: DateTime<Utc>) -> Result<Self, LeapSecond> {
        Self::new(instant)
    }
}

impl From<Timestamp> for DateTime<Utc> {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

/// The same leaf as `DateTime<Utc>`: a timestamp in nanoseconds. The
/// `DateTime` walk refuses only a leap second, which a `Timestamp` cannot
/// hold, so this never fails for its own sake.
impl Encrypt for Timestamp {
    const DEPTH: Option<usize> = depth::SCALAR;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit(sink)
    }
}

impl Encrypt for &Timestamp {
    const DEPTH: Option<usize> = depth::SCALAR;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (*self).visit(sink)
    }
}

/// Any unit, as for `DateTime<Utc>`. A decoded count is never a leap second.
impl FromScalar for Timestamp {
    const EXPECTED: &'static str = "timestamp";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        DateTime::<Utc>::from_scalar(ty, value).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use ::chrono::NaiveDate;

    use super::*;
    use crate::plaintext::{Int, TimeUnit};
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
        assert_eq!(Timestamp::new(leap()), Err(LeapSecond));
        assert_eq!(Timestamp::try_from(leap()), Err(LeapSecond));
        assert_eq!(LeapSecond.to_string(), "a leap second has no encoding");

        let last = NaiveDate::from_ymd_opt(2016, 12, 31)
            .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 999_999_999))
            .expect("ok")
            .and_utc();
        let ts = Timestamp::new(last).expect("not a leap second");
        assert_eq!(*ts.as_datetime(), last);
        assert_eq!(DateTime::<Utc>::from(ts), last);
    }

    /// The `DateTime` walk is what refuses a leap second, which is why the
    /// newtype exists; a `Timestamp` gives the same leaf for everything
    /// else.
    #[test]
    fn it_walks_as_the_datetime_it_holds() {
        let instant = DateTime::from_timestamp(1, 5).expect("ok");
        let ts = Timestamp::new(instant).expect("ok");
        assert_eq!(<Timestamp as Encrypt>::DEPTH, Some(0));
        assert_eq!(
            Timestamp::from_scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(1_000_000_005))
            ),
            Some(ts)
        );
        assert_eq!(
            Timestamp::from_scalar(None, Physical::Int(Int::I128(1))),
            None
        );

        assert_eq!(frame(ts), frame(instant));
        // The borrowed impl frames the same bytes as the owned one.
        let borrowed: &Timestamp = &ts;
        assert_eq!(frame(borrowed), frame(instant));

        assert!(matches!(
            plan::<_, (), _>(leap(), "aad"),
            Err(EncryptError::Source(_))
        ));
    }
}
