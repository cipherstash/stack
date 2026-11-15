//! UTC dates without a date crate: the SigV4 timestamp and the expiry
//! times in AWS credential responses.

use std::time::Duration;

use web_time::{SystemTime, UNIX_EPOCH};

/// The time source of a client: `SystemTime::now` unless a test sets
/// another.
pub use stack_kms_vendor::{system_clock, Clock};

/// The civil date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The day count since 1970-01-01 of a civil date (Howard Hinnant's
/// `days_from_civil`).
// Only the native credential providers parse expiry times.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The SigV4 date (`YYYYMMDD`) and timestamp (`YYYYMMDD'T'HHMMSS'Z'`) of
/// `time`, in UTC. A time before 1970 counts as 1970-01-01.
pub(crate) fn amz_date(time: SystemTime) -> (String, String) {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX / 2);
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let date = format!("{year:04}{month:02}{day:02}");
    let timestamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        rest / 3600,
        (rest / 60) % 60,
        rest % 60
    );
    (date, timestamp)
}

/// Parse an RFC 3339 UTC time as AWS returns it: `2026-11-05T12:00:00Z`,
/// with optional fractional seconds, and `Z` or `+00:00`. `None` for any
/// other form.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    let text = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))?;
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (time, fraction) = match time.split_once('.') {
        Some((time, fraction)) => (time, Some(fraction)),
        None => (time, None),
    };
    let mut time_parts = time.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let nanos = match fraction {
        Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
            let digits = &digits[..digits.len().min(9)];
            let value: u32 = digits.parse().ok()?;
            value * 10u32.pow(9 - digits.len() as u32)
        }
        Some(_) => return None,
        None => 0,
    };
    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn amz_date_formats_utc() {
        // 2015-08-30T12:36:00Z, the time of the AWS SigV4 test suite.
        let (date, timestamp) = amz_date(at(1_440_938_160));
        assert_eq!(date, "20150830");
        assert_eq!(timestamp, "20150830T123600Z");
        assert_eq!(amz_date(at(0)).1, "19700101T000000Z");
        // A leap day, and the last second of a year.
        assert_eq!(amz_date(at(951_782_400)).1, "20000229T000000Z");
        assert_eq!(amz_date(at(1_798_761_599)).1, "20261231T235959Z");
    }

    #[test]
    fn rfc3339_parses_the_forms_aws_returns() {
        assert_eq!(
            parse_rfc3339("2015-08-30T12:36:00Z"),
            Some(at(1_440_938_160))
        );
        assert_eq!(
            parse_rfc3339("2015-08-30T12:36:00+00:00"),
            Some(at(1_440_938_160))
        );
        assert_eq!(
            parse_rfc3339("2015-08-30T12:36:00.250Z"),
            Some(at(1_440_938_160) + Duration::from_millis(250))
        );
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(at(951_782_400)));
        for bad in [
            "2015-08-30T12:36:00",
            "2015-08-30 12:36:00Z",
            "2015-13-30T12:36:00Z",
            "2015-08-30T24:00:00Z",
            "2015-08-30T12:36:00.Z",
            "2015-08-30T12:36:00.1xZ",
            "1969-12-31T23:59:59Z",
            "",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_two_conversions_agree() {
        for days in [0, 1, 59, 60, 365, 10_957, 11_016, 20_000, 2_932_896] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
    }
}
