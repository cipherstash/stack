//! Typed inputs shared by conformance profiles.
use super::frames::frame;
use serde::Deserialize;
use stack_encrypt::dynamic::ValueFrame;
use vitaminc_aead::plaintext::{Int, Logical, Physical, Raw, TimeUnit};

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

/// The typed host value an `Input` names, as the engine holds it: every
/// integer at its own width, a logical type over its physical scalar, and
/// text parsed without rounding. A text the type cannot carry is a corpus
/// error, never a silently narrowed value.
pub fn value(input: &Input) -> ValueFrame {
    let int = |int: Int| frame(Raw(None, Physical::Int(int)));
    let text = input.text.as_str();
    match input.kind.as_str() {
        "bool" => frame(text.parse::<bool>().expect("bool")),
        "int8" => int(Int::I8(text.parse().expect("i8"))),
        "int16" => int(Int::I16(text.parse().expect("i16"))),
        "int32" => frame(text.parse::<i32>().expect("i32")),
        "int64" => frame(text.parse::<i64>().expect("i64")),
        "int128" => int(Int::I128(text.parse().expect("i128"))),
        "uint8" => int(Int::U8(text.parse().expect("u8"))),
        "uint16" => int(Int::U16(text.parse().expect("u16"))),
        "uint32" => int(Int::U32(text.parse().expect("u32"))),
        "uint64" => frame(text.parse::<u64>().expect("u64")),
        "uint128" => int(Int::U128(text.parse().expect("u128"))),
        "float32" => frame(parse_float::<f32>(text)),
        "float64" => frame(parse_float::<f64>(text)),
        "string" => frame(input.text.clone()),
        "bytes" => frame(super::unhex(text)),
        "date" => frame(Raw(
            Some(Logical::Date),
            Physical::Int(Int::I32(parse_date(text))),
        )),
        "timestamp" => frame(Raw(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(parse_timestamp(text))),
        )),
        "decimal" => {
            let (mantissa, scale) = parse_decimal(text);
            frame(Raw(
                Some(Logical::Decimal { scale }),
                Physical::Int(Int::I128(mantissa)),
            ))
        }
        "null" => {
            assert!(input.text.is_empty());
            frame(Raw(None, Physical::Null))
        }
        other => panic!("unsupported input kind {other}"),
    }
}

/// A float from its canonical spelling ([`canonical_float`]). Any other
/// text that parses, such as `1.00`, `1e+3`, `1E3`, `+1` or a rounded
/// decimal, is a corpus error, so every runner reads one spelling alike.
fn parse_float<F>(text: &str) -> F
where
    F: std::str::FromStr + std::fmt::Display + std::fmt::LowerExp + PartialEq + Copy,
    F::Err: std::fmt::Debug,
{
    let parsed: F = text.parse().expect("float");
    assert_eq!(
        canonical_float(parsed).as_deref(),
        Some(text),
        "{text}: not the shortest spelling of a representable value"
    );
    parsed
}

/// A float's canonical spelling: of its positional spelling (Rust's `{}`,
/// e.g. `34`, `-0`, `0.001`) and its scientific spelling (Rust's `{:e}`,
/// e.g. `1e3`, `3.4028235e38`, `5e-324`), both of the shortest digits that
/// round-trip, the shorter, and the positional one on a tie (`100`, not
/// `1e2`). The infinities are `inf` and `-inf`; `NaN` has none. Go's
/// `canonicalFloat` derives the same text from `strconv.FormatFloat`.
pub fn canonical_float<F>(value: F) -> Option<String>
where
    F: std::fmt::Display + std::fmt::LowerExp + PartialEq + Copy,
{
    #[allow(clippy::eq_op)]
    if value != value {
        return None;
    }
    let positional = format!("{value}");
    let scientific = format!("{value:e}");
    Some(if scientific.len() < positional.len() {
        scientific
    } else {
        positional
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian `YYYY-MM-DD`.
fn parse_date(text: &str) -> i32 {
    let (year, rest) = text.split_at(text.len() - 6);
    let year: i64 = year.parse().expect("year");
    let mut parts = rest[1..].split('-');
    let month: u32 = parts.next().expect("month").parse().expect("month");
    let day: u32 = parts.next().expect("day").parse().expect("day");
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    assert!(
        parts.next().is_none() && (1..=12).contains(&month) && (1..=days_in_month).contains(&day),
        "{text}: not a calendar date"
    );
    i32::try_from(days_from_civil(year, month, day)).expect("date in range")
}

/// Howard Hinnant's `days_from_civil`: the day count since the epoch of a
/// civil date, for any year.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Nanoseconds since the epoch of an RFC 3339 instant in UTC
/// (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`), to the nanosecond, with no rounding.
fn parse_timestamp(text: &str) -> i128 {
    let text = text.strip_suffix('Z').expect("a UTC instant ends in Z");
    let (date, time) = text.split_once('T').expect("a date and a time");
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut parts = clock.split(':');
    let hour: i128 = parts.next().expect("hour").parse().expect("hour");
    let minute: i128 = parts.next().expect("minute").parse().expect("minute");
    let second: i128 = parts.next().expect("second").parse().expect("second");
    assert!(parts.next().is_none() && hour < 24 && minute < 60 && second < 60);
    assert!(fraction.len() <= 9, "at most nanoseconds");
    let nanos: i128 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}").parse().expect("fraction")
    };
    let days = i128::from(parse_date(date));
    ((days * 86_400 + hour * 3_600 + minute * 60 + second) * 1_000_000_000) + nanos
}

/// A decimal's mantissa and scale from fixed-point text, keeping every
/// trailing zero: `-1234.5600` is `(-12345600, 4)`.
fn parse_decimal(text: &str) -> (i128, u8) {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = format!("{whole}{fraction}");
    let mantissa: i128 = digits.parse().expect("decimal digits");
    assert!(
        mantissa.unsigned_abs() < (1u128 << 96),
        "mantissa fits 96 bits"
    );
    let scale = u8::try_from(fraction.len()).expect("scale");
    assert!(scale <= 28, "scale at most 28");
    (mantissa, scale)
}

/// Inspect actual stored output, shared by scalar and runtime profiles.
pub fn stored_outputs(
    tree: &stack_encrypt::StackCipherText,
    field: &str,
) -> Option<(Vec<u8>, usize)> {
    use stack_encrypt::CipherText;
    let CipherText::Map(fields) = tree else {
        panic!("expected record")
    };
    assert!(fields.len() <= 1 && fields.iter().all(|(name, _)| name == field));
    let (_, node) = fields.iter().find(|(name, _)| name == field)?;
    let CipherText::Map(outputs) = node else {
        panic!("expected outputs")
    };
    assert_eq!(outputs.len(), 2);
    let CipherText::Single(leaf) = &outputs.iter().find(|(name, _)| name == "c").unwrap().1 else {
        panic!("expected ciphertext")
    };
    let CipherText::Passthrough(term) = &outputs.iter().find(|(name, _)| name == "eq").unwrap().1
    else {
        panic!("expected equality bytes")
    };
    Some((
        vitaminc_aead_frame::serde::from_slice::<&[u8]>(&term.0)
            .unwrap()
            .to_vec(),
        leaf.to_bytes().len(),
    ))
}
pub fn refusal(error: &stack_encrypt::dynamic::Error, code: &str, reason: &str, field: &str) {
    use miette::Diagnostic;
    assert_eq!(error.code().unwrap().to_string(), code);
    assert_eq!(error.reason().unwrap().as_str(), reason);
    assert_eq!(error.field(), Some(field));
}
