//! Host scalars as the ints and bytes their logical types are stored over,
//! and back: BigInt widths, and the text of a calendar date, a timestamp,
//! a decimal and a UUID.
//!
//! These conversions do not require a JavaScript environment.

use std::fmt;

use jiff::fmt::temporal::Pieces;
use rust_decimal::Decimal;
use vitaminc_aead::plaintext::kinds::{decimal as kinds_decimal, jiff as kinds_jiff};
use vitaminc_aead::{Int, Logical, TimeUnit};

/// Host scalar conversion errors. Node receives a TypeError with the same
/// stable code; errors contain no user plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConversionError {
    /// The integer fits neither `i128` nor `u128`.
    #[error("BigInt is outside the signed/unsigned 128-bit range")]
    IntegerRange,
    /// The calendar date is malformed or outside the supported range.
    #[error("invalid calendar date")]
    InvalidDate,
    /// The timestamp is malformed or outside the supported range.
    #[error("invalid or out-of-range timestamp")]
    InvalidTimestamp,
    /// The decimal is malformed or exceeds the supported precision or scale.
    #[error("invalid or out-of-range decimal")]
    InvalidDecimal,
    /// The decimal is NaN or infinite.
    #[error("decimal must be finite")]
    NonFiniteDecimal,
    /// The UUID text is malformed.
    #[error("invalid UUID")]
    InvalidUuid,
}

impl ConversionError {
    /// Return the stable `ERR_*` code exposed to JavaScript callers.
    pub fn code(self) -> &'static str {
        match self {
            Self::IntegerRange => "ERR_INTEGER_RANGE",
            Self::InvalidDate => "ERR_INVALID_DATE",
            Self::InvalidTimestamp => "ERR_INVALID_TIMESTAMP",
            Self::InvalidDecimal => "ERR_INVALID_DECIMAL",
            Self::NonFiniteDecimal => "ERR_NON_FINITE_DECIMAL",
            Self::InvalidUuid => "ERR_INVALID_UUID",
        }
    }
}

/// A BigInt as the narrowest int that holds it. Smallest width first,
/// preferring signed when both signed and unsigned at that width fit. This
/// rule is frozen for JS BigInt host conversion.
pub(crate) fn bigint(negative: bool, words: &[u64]) -> Result<Int, ConversionError> {
    if words
        .get(2..)
        .is_some_and(|tail| tail.iter().any(|&word| word != 0))
    {
        return Err(ConversionError::IntegerRange);
    }
    let magnitude = u128::from(words.first().copied().unwrap_or(0))
        .wrapping_add(u128::from(words.get(1).copied().unwrap_or(0)) << 64);
    if negative && magnitude != 0 {
        if magnitude > (1u128 << 127) {
            return Err(ConversionError::IntegerRange);
        }
        Ok(signed((magnitude as i128).wrapping_neg()))
    } else {
        Ok(unsigned(magnitude))
    }
}

fn signed(value: i128) -> Int {
    if let Ok(v) = i8::try_from(value) {
        Int::I8(v)
    } else if let Ok(v) = i16::try_from(value) {
        Int::I16(v)
    } else if let Ok(v) = i32::try_from(value) {
        Int::I32(v)
    } else if let Ok(v) = i64::try_from(value) {
        Int::I64(v)
    } else {
        Int::I128(value)
    }
}

fn unsigned(value: u128) -> Int {
    if let Ok(v) = i8::try_from(value) {
        Int::I8(v)
    } else if let Ok(v) = u8::try_from(value) {
        Int::U8(v)
    } else if let Ok(v) = i16::try_from(value) {
        Int::I16(v)
    } else if let Ok(v) = u16::try_from(value) {
        Int::U16(v)
    } else if let Ok(v) = i32::try_from(value) {
        Int::I32(v)
    } else if let Ok(v) = u32::try_from(value) {
        Int::U32(v)
    } else if let Ok(v) = i64::try_from(value) {
        Int::I64(v)
    } else if let Ok(v) = u64::try_from(value) {
        Int::U64(v)
    } else if let Ok(v) = i128::try_from(value) {
        Int::I128(v)
    } else {
        Int::U128(value)
    }
}

/// A nanosecond count as the narrowest int the leaf codec can carry it in.
fn nanos_int(nanos: i128) -> Int {
    match i64::try_from(nanos) {
        Ok(v) => Int::I64(v),
        Err(_) => Int::I128(nanos),
    }
}

/// `YYYY-MM-DD` as days since 1970-01-01, spelled as jiff and JavaScript
/// write it: a year from 0000 to 9999 in four digits, and a negative year
/// as a sign and six digits (`-000005-03-01`).
pub(crate) fn date(text: &str) -> Result<Int, ConversionError> {
    let value: jiff::civil::Date = text.parse().map_err(|_| ConversionError::InvalidDate)?;
    // jiff reads other spellings too (`20240229`, `+002024-02-29`, a date
    // with a time). Only the one it writes is taken, so a date has one.
    if !displays_as(&value, text) {
        return Err(ConversionError::InvalidDate);
    }
    Ok(Int::I32(kinds_jiff::date_days(value)))
}

/// Whether `value` displays as exactly `text`. The display is compared as it
/// is written rather than collected into a `String`, so no unwiped copy of
/// the plaintext is left behind.
fn displays_as(value: &impl fmt::Display, text: &str) -> bool {
    struct Rest<'a>(&'a str);
    impl fmt::Write for Rest<'_> {
        fn write_str(&mut self, part: &str) -> fmt::Result {
            self.0 = self.0.strip_prefix(part).ok_or(fmt::Error)?;
            Ok(())
        }
    }
    let mut rest = Rest(text);
    fmt::write(&mut rest, format_args!("{value}")).is_ok() && rest.0.is_empty()
}

/// A day count as `YYYY-MM-DD`, if it is within the wire's range.
pub(crate) fn date_text(days: Int) -> Option<String> {
    kinds_jiff::date(days).map(|date| date.to_string())
}

/// RFC 3339 text as nanoseconds since the epoch, with a negative year
/// spelled as a sign and six digits, as jiff and JavaScript write it
/// (`-000005-03-01T12:00:00Z`), so a decrypted timestamp encrypts again. A
/// leap second has no count and is refused, as the leaf codec refuses it.
pub(crate) fn timestamp(text: &str) -> Result<Int, ConversionError> {
    if !is_rfc3339(text) {
        return Err(ConversionError::InvalidTimestamp);
    }
    // jiff reads the fields and checks their values. The instant is
    // counted here, not by jiff's `Offset::to_timestamp`, which in jiff
    // 1.0.0 can return one before jiff's minimum (BurntSushi/jiff#714).
    let pieces = Pieces::parse(text).map_err(|_| ConversionError::InvalidTimestamp)?;
    let (Some(time), Some(offset)) = (pieces.time(), pieces.to_numeric_offset()) else {
        return Err(ConversionError::InvalidTimestamp);
    };
    let seconds = i128::from(kinds_jiff::date_days(pieces.date())) * 86_400
        + i128::from(time.hour()) * 3_600
        + i128::from(time.minute()) * 60
        + i128::from(time.second())
        - i128::from(offset.seconds());
    let nanos = seconds * 1_000_000_000 + i128::from(time.subsec_nanosecond());
    vitaminc_aead::plaintext::kinds::timestamp_nanos(TimeUnit::Nanos, Int::I128(nanos))
        .map(nanos_int)
        .ok_or(ConversionError::InvalidTimestamp)
}

/// Whether `text` has RFC 3339's shape: a date, `T`, `HH:MM:SS`, a
/// fraction of one to nine digits or none, and `Z` or `±HH:MM` with an
/// hour of at most 23. `t` and `z` may be lower case, and a space may
/// stand for `T`.
///
/// jiff's parser reads much more than this (no seconds, the basic format,
/// a comma, a time zone annotation, an offset of 24 or 25 hours), and
/// reads a leap second as the second before it. So the shape is checked
/// first, and a leap second and such an offset refused; jiff checks the
/// other values.
fn is_rfc3339(text: &str) -> bool {
    let year = if text.starts_with(['+', '-']) {
        "s999999"
    } else {
        "9999"
    };
    let Some(rest) = after(text, year).and_then(|rest| after(rest, "-99-99T99:99:99")) else {
        return false;
    };
    if text[..text.len() - rest.len()].ends_with("60") {
        return false;
    }
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if !(1..=9).contains(&digits) {
                return false;
            }
            &fraction[digits..]
        }
        None => rest,
    };
    // The offset's two hour digits compare as text, since both are ASCII
    // digits.
    matches!(rest, "Z" | "z") || (after(rest, "s99:99") == Some("") && &rest[1..3] < "24")
}

/// What follows a prefix of `text` that has `shape`, where `9` stands for
/// an ASCII digit, `s` for `+` or `-`, `T` for `T`, `t` or a space, and
/// any other byte for itself.
fn after<'a>(text: &'a str, shape: &str) -> Option<&'a str> {
    let head = text.as_bytes().get(..shape.len())?;
    head.iter()
        .zip(shape.bytes())
        .all(|(&byte, want)| match want {
            b'9' => byte.is_ascii_digit(),
            b's' => matches!(byte, b'+' | b'-'),
            b'T' => matches!(byte, b'T' | b't' | b' '),
            _ => byte == want,
        })
        // The prefix is ASCII, so it ends on a character boundary.
        .then(|| &text[shape.len()..])
}

/// A JavaScript `Date`'s millisecond count, as the `I64` it is stored as
/// under `Timestamp(Millis)`. Refused when it is not a whole number of
/// milliseconds (`Invalid Date` is NaN) or lies outside the wire's range.
pub(crate) fn date_millis(ms: f64) -> Result<Int, ConversionError> {
    if !ms.is_finite() || ms.fract() != 0.0 {
        return Err(ConversionError::InvalidTimestamp);
    }
    // `as` saturates, and anything that saturates is out of range anyway.
    let count = Int::I64(ms as i64);
    if Logical::Timestamp(TimeUnit::Millis).admits(&vitaminc_aead::Physical::Int(count)) {
        Ok(count)
    } else {
        Err(ConversionError::InvalidTimestamp)
    }
}

/// The millisecond count a stored timestamp has as a JavaScript `Date`, if
/// it is whole milliseconds. Every stored timestamp is inside the wire's
/// range, which is narrower than `Date`'s, so the count always fits.
pub(crate) fn timestamp_js_millis(unit: TimeUnit, count: Int) -> Option<f64> {
    let nanos = vitaminc_aead::plaintext::kinds::timestamp_nanos(unit, count)?;
    kinds_jiff::timestamp_count(TimeUnit::Millis, nanos).map(|ms| ms as f64)
}

/// A stored timestamp as RFC 3339 text with nanoseconds, for the
/// `VcTimestamp` wrapper.
pub(crate) fn timestamp_text(unit: TimeUnit, count: Int) -> Option<String> {
    kinds_jiff::timestamp(unit, count).map(|instant| format!("{instant:.9}"))
}

/// Fixed-point decimal text as a scale and mantissa.
pub(crate) fn decimal(text: &str) -> Result<(u8, Int), ConversionError> {
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    // Compared in place, without a lowercase copy of the plaintext.
    let non_finite = ["nan", "inf", "infinity"];
    if non_finite.iter().any(|s| unsigned.eq_ignore_ascii_case(s)) {
        return Err(ConversionError::NonFiniteDecimal);
    }
    // Fixed-point only, matching Go. Refuse separators/exponents rather than
    // letting a library parser choose rounding or representation policy.
    let mut parts = unsigned.split('.');
    let integral = parts.next().unwrap_or("");
    let fraction = parts.next();
    if integral.is_empty()
        || !integral.bytes().all(|c| c.is_ascii_digit())
        || fraction.is_some_and(|part| {
            part.is_empty() || part.len() > 28 || !part.bytes().all(|c| c.is_ascii_digit())
        })
        || parts.next().is_some()
    {
        return Err(ConversionError::InvalidDecimal);
    }
    // A negative zero parses as zero, which is what the leaf codec stores.
    let (scale, mantissa) = Decimal::from_str_exact(text)
        .map(kinds_decimal::parts)
        .map_err(|_| ConversionError::InvalidDecimal)?;
    Ok((scale, Int::I128(mantissa)))
}

/// A stored decimal as fixed-point text with its scale, for the `VcDecimal`
/// wrapper.
pub(crate) fn decimal_text(scale: u8, mantissa: Int) -> Option<String> {
    kinds_decimal::decimal(scale, mantissa).map(|value| value.to_string())
}

/// Hyphenated hexadecimal UUID text as its sixteen bytes. Case is accepted
/// either way; braces, URNs and other spellings are not.
pub(crate) fn uuid(text: &str) -> Result<[u8; 16], ConversionError> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return Err(ConversionError::InvalidUuid);
    }
    let mut out = [0u8; 16];
    let mut digits = bytes.iter().filter(|&&b| b != b'-');
    for byte in &mut out {
        let hi = digits.next().and_then(|&d| (d as char).to_digit(16));
        let lo = digits.next().and_then(|&d| (d as char).to_digit(16));
        match (hi, lo) {
            (Some(hi), Some(lo)) => *byte = (hi * 16 + lo) as u8,
            _ => return Err(ConversionError::InvalidUuid),
        }
    }
    Ok(out)
}

/// Sixteen bytes as lowercase hyphenated UUID text.
pub(crate) fn uuid_text(bytes: &[u8]) -> Option<String> {
    let bytes: &[u8; 16] = bytes.try_into().ok()?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::plaintext::kinds::{MAX_TIMESTAMP_NANOS, MIN_TIMESTAMP_NANOS};

    fn width(int: Int) -> &'static str {
        match int {
            Int::I8(_) => "i8",
            Int::U8(_) => "u8",
            Int::I16(_) => "i16",
            Int::U16(_) => "u16",
            Int::I32(_) => "i32",
            Int::U32(_) => "u32",
            Int::I64(_) => "i64",
            Int::U64(_) => "u64",
            Int::I128(_) => "i128",
            Int::U128(_) => "u128",
        }
    }

    #[test]
    fn bigint_boundaries_choose_the_smallest_width() {
        let positive = [
            (0, "i8"),
            (127, "i8"),
            (128, "u8"),
            (255, "u8"),
            (256, "i16"),
            (32767, "i16"),
            (32768, "u16"),
            (65535, "u16"),
            (65536, "i32"),
            (i32::MAX as u128, "i32"),
            (i32::MAX as u128 + 1, "u32"),
            (u32::MAX as u128, "u32"),
            (u32::MAX as u128 + 1, "i64"),
            (i64::MAX as u128, "i64"),
            (i64::MAX as u128 + 1, "u64"),
            (u64::MAX as u128, "u64"),
            (u64::MAX as u128 + 1, "i128"),
            (i128::MAX as u128, "i128"),
            (i128::MAX as u128 + 1, "u128"),
            (u128::MAX, "u128"),
        ];
        for (value, expected) in positive {
            let words = [value as u64, (value >> 64) as u64];
            let int = bigint(false, &words).expect("in range");
            assert_eq!(width(int), expected, "{value}");
            assert_eq!(int.to_u128(), Some(value));
        }
        let negative = [
            (128u128, "i8"),
            (129, "i16"),
            (32768, "i16"),
            (32769, "i32"),
            (1 << 31, "i32"),
            ((1 << 31) + 1, "i64"),
            (1 << 63, "i64"),
            ((1 << 63) + 1, "i128"),
            (1 << 127, "i128"),
        ];
        for (magnitude, expected) in negative {
            let int =
                bigint(true, &[magnitude as u64, (magnitude >> 64) as u64]).expect("in range");
            assert_eq!(width(int), expected, "-{magnitude}");
            assert_eq!(int.to_i128(), Some((magnitude as i128).wrapping_neg()));
        }
        assert_eq!(bigint(true, &[0, 1 << 63]), Ok(Int::I128(i128::MIN)));
        assert_eq!(bigint(false, &[]), Ok(Int::I8(0)));
        assert_eq!(bigint(true, &[0]), Ok(Int::I8(0)), "negative zero");
        assert_eq!(
            bigint(false, &[1, 0, 0]),
            Ok(Int::I8(1)),
            "leading zero word"
        );
        assert_eq!(
            bigint(true, &[1, 1 << 63]),
            Err(ConversionError::IntegerRange)
        );
        assert_eq!(
            bigint(false, &[0, 0, 1]),
            Err(ConversionError::IntegerRange)
        );
    }

    #[test]
    fn dates_are_day_counts_and_round_trip_as_text() {
        assert_eq!(date("1970-01-01"), Ok(Int::I32(0)));
        assert_eq!(date("2024-02-29"), Ok(Int::I32(19782)));
        assert_eq!(date("0000-01-01"), Ok(Int::I32(-719_528)));
        assert_eq!(date("-009999-01-01"), Ok(Int::I32(-4_371_587)));
        assert_eq!(date("9999-12-31"), Ok(Int::I32(2_932_896)));
        for text in [
            "2024-02-29",
            "0000-01-01",
            "9999-12-31",
            "-000005-03-01",
            "-009999-01-01",
        ] {
            assert_eq!(date_text(date(text).expect("valid")).as_deref(), Some(text));
        }
        for invalid in [
            "2023-02-29",
            "2024-2-9",
            "",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00",
            // Spellings jiff reads but does not write.
            "20240229",
            "+002024-02-29",
            "-0005-03-01",
            // Past the wire's range, which is jiff's.
            "10000-01-01",
            "+010000-01-01",
            "-010000-01-01",
        ] {
            assert_eq!(
                date(invalid),
                Err(ConversionError::InvalidDate),
                "{invalid}"
            );
        }
        assert_eq!(date_text(Int::I128(i128::MAX)), None);
    }

    #[test]
    fn a_value_displays_as_text_only_when_every_byte_matches() {
        assert!(displays_as(&"2024-02-29", "2024-02-29"));
        assert!(displays_as(&"", ""));
        assert!(!displays_as(&"2024-02-29", "2024-02-2"), "text too short");
        assert!(!displays_as(&"2024-02-29", "2024-02-290"), "text too long");
        assert!(!displays_as(&"2024-02-29", "2024-02-28"), "a byte differs");
    }

    #[test]
    fn timestamps_are_nanosecond_counts_and_refuse_leap_seconds() {
        assert_eq!(
            timestamp("1970-01-01T00:00:00.123Z"),
            Ok(Int::I64(123_000_000))
        );
        assert_eq!(
            timestamp("1969-12-31T23:59:59.999999999Z"),
            Ok(Int::I64(-1))
        );
        // ADR 0001 section 3: a leap second has no count and is refused.
        assert_eq!(
            timestamp("2016-12-31T23:59:60.123456789Z"),
            Err(ConversionError::InvalidTimestamp)
        );
        // Each comes back as the text it went in as, in i128 when i64 is
        // too narrow. A negative year has a sign and six digits.
        for (text, expected_width) in [
            ("-000005-03-01T12:00:00.000000001Z", "i128"),
            ("2262-04-11T23:47:16.854775807Z", "i64"),
            ("2262-04-11T23:47:16.854775808Z", "i128"),
            // The ends of the wire's range, which is jiff's.
            ("-009999-01-02T01:59:59.000000000Z", "i128"),
            ("9999-12-30T22:00:00.999999999Z", "i128"),
        ] {
            let count = timestamp(text).expect("valid");
            assert_eq!(width(count), expected_width, "{text}");
            assert_eq!(
                timestamp_text(TimeUnit::Nanos, count).as_deref(),
                Some(text)
            );
        }
        // An offset is applied, the other spellings RFC 3339 allows are
        // read, and so is a year with a `+` and six digits, as ISO 8601
        // writes it.
        for (text, utc) in [
            (
                "-000005-03-01T12:00:00+01:00",
                "-000005-03-01T11:00:00.000000000Z",
            ),
            (
                "2024-02-29T12:00:00.5-01:30",
                "2024-02-29T13:30:00.500000000Z",
            ),
            ("2024-02-29t12:00:00z", "2024-02-29T12:00:00.000000000Z"),
            (
                "2024-02-29 12:00:00-00:00",
                "2024-02-29T12:00:00.000000000Z",
            ),
            (
                "+002024-02-29T12:00:00.1Z",
                "2024-02-29T12:00:00.100000000Z",
            ),
            // The widest offsets RFC 3339 allows.
            (
                "2024-02-29T12:00:00+23:59",
                "2024-02-28T12:01:00.000000000Z",
            ),
            (
                "2024-02-29T12:00:00-23:59",
                "2024-03-01T11:59:00.000000000Z",
            ),
        ] {
            let count = timestamp(text).expect(text);
            assert_eq!(timestamp_text(TimeUnit::Nanos, count).as_deref(), Some(utc));
        }
        for invalid in [
            "",
            "bad",
            "+012000-01-01T00:00:00Z",
            "+012000-13-01T00:00:00Z",
            "-0005-03-01T12:00:00Z",
            "-000005-03-01T12:00:00",
            "-000005-03-01",
            // Past either end of the wire's range: jiff 1.0.0 would make
            // the first an instant before its own minimum.
            "-009999-01-02T01:59:58.5Z",
            "-009999-01-01T00:00:00Z",
            "9999-12-30T22:00:01Z",
            "9999-12-31T00:00:00+01:00",
            // Spellings jiff reads that are not RFC 3339.
            "2024-02-29T12:00Z",
            "20240229T120000Z",
            "2024-02-29T12:00:00Z[UTC]",
            "2024-02-29T12:00:00,5Z",
            "2024-02-29T12:00:00+0100",
            "2024-02-29T12:00:00+01",
            "2024-02-29T12:00:00.Z",
            "2024-02-29T12:00:00.1234567891Z",
            "2024-02-29X12:00:00Z",
            "2024-02-29T12:00:00Zx",
            // Values out of range in each field.
            "2024-02-30T12:00:00Z",
            "2024-02-29T24:00:00Z",
            "2024-02-29T12:60:00Z",
            "2024-02-29T12:00:61Z",
            "2024-02-29T12:00:00+23:60",
            // jiff reads an offset of up to 25 hours; RFC 3339 stops at 23.
            "2024-02-29T12:00:00+24:00",
            "2024-02-29T12:00:00-25:59",
            "2024-02-29T12:00:00+26:00",
        ] {
            assert_eq!(
                timestamp(invalid),
                Err(ConversionError::InvalidTimestamp),
                "{invalid}"
            );
        }
    }

    /// `timestamp` counts the instant itself, so compare its count with
    /// jiff's own for many dates, times, fractions and offsets. The years
    /// stay away from the ends of the range, where jiff 1.0.0 miscounts
    /// (BurntSushi/jiff#714) and an offset can carry the instant out.
    #[test]
    fn a_timestamp_count_is_the_one_jiff_counts() {
        // A fixed xorshift sequence, so a failure can be reproduced.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut below = |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n) as i64
        };
        for _ in 0..20_000 {
            let year = below(19_981) - 9_990;
            let month = below(12) + 1;
            let days_in_month = jiff::civil::Date::new(year as i16, month as i8, 1)
                .expect("a date in range")
                .days_in_month();
            let day = below(days_in_month as u64) + 1;
            let year = if (0..=9_999).contains(&year) {
                format!("{year:04}")
            } else {
                format!("{}{:06}", if year < 0 { '-' } else { '+' }, year.abs())
            };
            let (hour, minute, second) = (below(24), below(60), below(60));
            let fraction = match below(10) as usize {
                0 => String::new(),
                digits => format!(".{:09}", below(1_000_000_000))[..=digits].to_owned(),
            };
            let offset = match below(3) {
                0 => "Z".to_owned(),
                sign => format!(
                    "{}{:02}:{:02}",
                    if sign == 1 { '+' } else { '-' },
                    below(24),
                    below(60)
                ),
            };
            let text = format!(
                "{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}{offset}"
            );
            let expected = text
                .parse::<jiff::Timestamp>()
                .unwrap_or_else(|e| panic!("jiff reads {text}: {e}"))
                .as_nanosecond();
            assert_eq!(
                timestamp(&text).ok().and_then(|count| count.to_i128()),
                Some(expected),
                "{text}"
            );
        }
    }

    #[test]
    fn a_js_date_is_its_millisecond_count() {
        assert_eq!(date_millis(-1.0), Ok(Int::I64(-1)));
        assert_eq!(date_millis(0.0), Ok(Int::I64(0)));
        assert_eq!(
            date_millis(1_700_000_000_000.0),
            Ok(Int::I64(1_700_000_000_000))
        );
        for invalid in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.5,
            // Inside `Date`'s range but outside the wire's.
            8_640_000_000_000_000.0,
            -8_640_000_000_000_000.0,
        ] {
            assert_eq!(
                date_millis(invalid),
                Err(ConversionError::InvalidTimestamp),
                "{invalid}"
            );
        }
    }

    #[test]
    fn a_stored_timestamp_is_a_js_date_only_when_it_is_whole_milliseconds() {
        assert_eq!(
            timestamp_js_millis(TimeUnit::Millis, Int::I64(123)),
            Some(123.0)
        );
        assert_eq!(
            timestamp_js_millis(TimeUnit::Nanos, Int::I64(123_000_000)),
            Some(123.0)
        );
        assert_eq!(
            timestamp_js_millis(TimeUnit::Micros, Int::I64(-1_000)),
            Some(-1.0)
        );
        // Sub-millisecond precision needs the wrapper.
        assert_eq!(timestamp_js_millis(TimeUnit::Nanos, Int::I64(-1)), None);
        assert_eq!(timestamp_js_millis(TimeUnit::Micros, Int::I64(1)), None);
        // The wire's whole range fits a `Date`: its limits are under
        // 4e14 milliseconds either way, inside `Date`'s ±8.64e15.
        for limit in [MIN_TIMESTAMP_NANOS, MAX_TIMESTAMP_NANOS] {
            let ms = timestamp_js_millis(TimeUnit::Millis, Int::I64((limit / 1_000_000) as i64))
                .expect("whole milliseconds at the bound");
            assert!(ms.abs() <= 8_640_000_000_000_000.0, "{ms}");
        }
        // Out of the wire's range entirely.
        assert_eq!(
            timestamp_js_millis(TimeUnit::Nanos, Int::I128(i128::MAX)),
            None
        );
        assert_eq!(timestamp_text(TimeUnit::Nanos, Int::I128(i128::MAX)), None);
    }

    #[test]
    fn decimals_are_exact_and_negative_zero_is_zero() {
        for text in ["NaN", "+nan", "-NaN", "inf", "+Infinity", "-Infinity"] {
            assert_eq!(
                decimal(text),
                Err(ConversionError::NonFiniteDecimal),
                "{text}"
            );
        }
        for text in [
            "",
            "1e2",
            "1_000",
            "1.5_0",
            ".1",
            "1.",
            "1.2.3",
            " 1",
            "1a",
            "1.a",
            "0.00000000000000000000000000001",
            "79228162514264337593543950336",
        ] {
            assert_eq!(
                decimal(text),
                Err(ConversionError::InvalidDecimal),
                "{text}"
            );
        }
        assert_eq!(decimal("1.50"), Ok((2, Int::I128(150))));
        assert_eq!(decimal("+1.50"), Ok((2, Int::I128(150))));
        assert_eq!(decimal("-1.50"), Ok((2, Int::I128(-150))));
        // ADR 0001 section 3: a negative zero reads back as zero, scale kept.
        assert_eq!(decimal("-0.00"), Ok((2, Int::I128(0))));
        assert_eq!(decimal_text(2, Int::I128(0)).as_deref(), Some("0.00"));
        for text in [
            "1.50",
            "-79228162514264337593543950335",
            "0.0000000000000000000000000001",
        ] {
            let (scale, mantissa) = decimal(text).expect("valid");
            assert_eq!(decimal_text(scale, mantissa).as_deref(), Some(text));
        }
        assert_eq!(decimal_text(29, Int::I128(1)), None);
    }

    #[test]
    fn uuids_are_sixteen_bytes_in_hyphenated_hex() {
        let text = "123e4567-e89b-12d3-a456-426614174000";
        let bytes = uuid(text).expect("valid");
        assert_eq!(bytes[0..4], [0x12, 0x3e, 0x45, 0x67]);
        assert_eq!(uuid_text(&bytes).as_deref(), Some(text));
        assert_eq!(uuid(&text.to_uppercase()), Ok(bytes));
        for invalid in [
            "",
            "123e4567e89b12d3a456426614174000",
            "{123e4567-e89b-12d3-a456-426614174000}",
            "123e4567-e89b-12d3-a456-42661417400g",
            "123e4567-e89b-12d3-a456-4266141740000",
            "123e4567-e89b-12d3-a456-42661417400",
            "123e4567-e89b-12d3-a456-4266141740\u{e9}",
        ] {
            assert_eq!(
                uuid(invalid),
                Err(ConversionError::InvalidUuid),
                "{invalid:?}"
            );
        }
        assert_eq!(uuid_text(&[0; 15]), None);
    }

    #[test]
    fn every_error_has_a_stable_code_and_a_message() {
        for error in [
            ConversionError::IntegerRange,
            ConversionError::InvalidDate,
            ConversionError::InvalidTimestamp,
            ConversionError::InvalidDecimal,
            ConversionError::NonFiniteDecimal,
            ConversionError::InvalidUuid,
        ] {
            assert!(error.code().starts_with("ERR_"));
            assert!(!error.to_string().is_empty());
        }
    }
}
