//! Scalars on the wire: in a sealed leaf, and in a transport frame.
//!
//! Today's tag table ([`tags`]) is read as **shorthand** for a physical kind
//! plus a logical type: `UINT32` is a plain int, `DATE` is `Logical::Date`
//! over an int, and so on. Every existing leaf and frame is therefore still
//! valid, byte for byte.
//!
//! A logical type with no tag of its own travels in the **generic
//! envelope**: [`tags::LOGICAL`], the logical id, the one-byte parameter,
//! then the plain physical scalar. A reader that does not know the id still
//! reads the physical value and keeps the annotation as
//! [`Logical::Unknown`]. There is exactly one encoding per value: an
//! envelope is refused where a shorthand tag exists.
//!
//! The two forms differ in one way: a frame gives text and bytes a `u32`
//! little-endian length, because other nodes follow; a leaf does not,
//! because the sealed plaintext ends where the payload does. The functions
//! here take the [`Form`] so the transport frame and the leaf share one
//! codec and cannot drift.
//!
//! The codec has no dependency on chrono or `rust_decimal`: the `DATE`,
//! `TIMESTAMP` and `DECIMAL` payloads are written from, and read into, the
//! int they are logical types over.
//!
//! Two encodings that `vitaminc-aead-value` accepts have no
//! physical-plus-logical form, so this codec does not round-trip them:
//!
//! - A `TIMESTAMP` with nanoseconds of 1,000,000,000 or more is chrono's
//!   leap second. It has no count in any unit and is refused.
//! - A `DECIMAL` with the sign bit set on a zero mantissa reads as zero,
//!   and zero is always written without the sign.

use crate::plaintext::kinds::{Float, Int, Logical, Physical, TimeUnit, MAX_DECIMAL_SCALE};
use crate::tags;

/// Which wire form a scalar is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// A node in a transport frame: text and bytes carry a `u32` length.
    Frame,
    /// A sealed leaf: text and bytes run to the end.
    Leaf,
}

/// Why a scalar could not be written or read.
///
/// `#[non_exhaustive]`, so a reason can be added (for example when
/// [`tags::LOGICAL_LONG`] gets a meaning) without breaking a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScalarError {
    /// The value is not a valid value of its logical type.
    Invalid,
    /// Text or bytes longer than a `u32` length (frame form only).
    TooLong,
    /// The bytes are not a well-formed scalar: an unknown tag, a short
    /// payload, invalid UTF-8, trailing bytes in a leaf, or an envelope
    /// where a shorthand tag exists.
    Malformed,
}

impl core::fmt::Display for ScalarError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "value is not valid for its logical type",
            Self::TooLong => "text or bytes too long for a u32 length",
            Self::Malformed => "malformed scalar",
        })
    }
}

/// Built on [`core::error::Error`], so the codec needs nothing from `std`.
impl core::error::Error for ScalarError {}

/// Days from 0001-01-01 (day 1, chrono's "days from CE") to 1970-01-01.
const EPOCH_DAYS_FROM_CE: i32 = 719_163;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
/// rust_decimal's flag word: the sign bit and the scale byte are the only
/// bits that may be set.
const DECIMAL_SIGN: u32 = 1 << 31;
const DECIMAL_SCALE_SHIFT: u32 = 16;
const DECIMAL_SCALE_MASK: u32 = 0xFF << DECIMAL_SCALE_SHIFT;
/// Every flag bit that is neither the sign nor the scale. Written out
/// rather than derived, so it reads as the wire constant it is; a test
/// pins it to the two masks.
const DECIMAL_RESERVED: u32 = 0x7F00_FFFF;

/// Write one scalar in `form` onto `out`. Fails if the value is not valid
/// for its logical type, or (in a frame) too long.
pub fn write(
    ty: Option<Logical>,
    v: Physical<'_>,
    form: Form,
    out: &mut Vec<u8>,
) -> Result<(), ScalarError> {
    // Check everything that can fail before writing anything, so an error
    // never leaves a dangling tag in `out`.
    if let Physical::Text(s) = v {
        length_prefix(form, s.len())?;
    }
    if let Physical::Bytes(b) = v {
        length_prefix(form, b.len())?;
    }
    let Some(ty) = ty else {
        return write_physical(v, form, out);
    };
    if !ty.admits(&v) {
        return Err(ScalarError::Invalid);
    }
    match (ty, v) {
        (Logical::Undefined, _) => out.push(tags::UNDEFINED),
        (Logical::Date, Physical::Int(days)) => {
            // `admits` checked the range, which is inside i32 with room for
            // the epoch offset.
            let days = i32::try_from(days.to_i128().ok_or(ScalarError::Invalid)?)
                .map_err(|_| ScalarError::Invalid)?;
            let from_ce = days
                .checked_add(EPOCH_DAYS_FROM_CE)
                .ok_or(ScalarError::Invalid)?;
            out.push(tags::DATE);
            out.extend_from_slice(&from_ce.to_le_bytes());
        }
        (Logical::Timestamp(TimeUnit::Nanos), Physical::Int(count)) => {
            let nanos = count.to_i128().ok_or(ScalarError::Invalid)?;
            let seconds = i64::try_from(nanos.div_euclid(NANOS_PER_SECOND))
                .map_err(|_| ScalarError::Invalid)?;
            let sub = nanos.rem_euclid(NANOS_PER_SECOND) as u32;
            out.push(tags::TIMESTAMP);
            out.extend_from_slice(&seconds.to_le_bytes());
            out.extend_from_slice(&sub.to_le_bytes());
        }
        (Logical::Decimal { scale }, Physical::Int(mantissa)) => {
            let mantissa = mantissa.to_i128().ok_or(ScalarError::Invalid)?;
            let mut flags = u32::from(scale) << DECIMAL_SCALE_SHIFT;
            if mantissa < 0 {
                flags |= DECIMAL_SIGN;
            }
            let magnitude = mantissa.unsigned_abs();
            out.push(tags::DECIMAL);
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&(magnitude as u32).to_le_bytes());
            out.extend_from_slice(&((magnitude >> 32) as u32).to_le_bytes());
            out.extend_from_slice(&((magnitude >> 64) as u32).to_le_bytes());
        }
        (ty, v) => {
            let (id, param) = ty.to_wire();
            out.extend_from_slice(&[tags::LOGICAL, id, param]);
            write_physical(v, form, out)?;
        }
    }
    Ok(())
}

/// Write one sealed leaf's plaintext.
///
/// # Examples
///
/// A date, 11,017 days after 1970-01-01, under today's `DATE` tag. The
/// payload is chrono's day count from the common era, little-endian.
///
/// ```
/// use vitaminc_aead::leaf::{read_leaf, write_leaf, ScalarError};
/// use vitaminc_aead::plaintext::{Int, Logical, Physical};
///
/// let date = (Some(Logical::Date), Physical::Int(Int::I32(11_017)));
/// let mut out = Vec::new();
/// write_leaf(date.0, date.1, &mut out)?;
/// assert_eq!(out, [0x12, 0x44, 0x24, 0x0B, 0x00]);
/// assert_eq!(read_leaf(&out)?, date);
/// # Ok::<(), ScalarError>(())
/// ```
pub fn write_leaf(
    ty: Option<Logical>,
    v: Physical<'_>,
    out: &mut Vec<u8>,
) -> Result<(), ScalarError> {
    write(ty, v, Form::Leaf, out)
}

/// Whether `ty` is written with one of today's tags rather than the
/// envelope.
fn has_shorthand(ty: Logical) -> bool {
    matches!(
        ty,
        Logical::Undefined
            | Logical::Date
            | Logical::Timestamp(TimeUnit::Nanos)
            | Logical::Decimal { .. }
    )
}

/// The `u32` length prefix a text or bytes payload of `len` carries in
/// `form`. A leaf has none: its payload runs to the end of the plaintext.
fn length_prefix(form: Form, len: usize) -> Result<Option<u32>, ScalarError> {
    match form {
        Form::Frame => u32::try_from(len)
            .map(Some)
            .map_err(|_| ScalarError::TooLong),
        Form::Leaf => Ok(None),
    }
}

fn write_physical(v: Physical<'_>, form: Form, out: &mut Vec<u8>) -> Result<(), ScalarError> {
    let mut variable = |tag, bytes: &[u8]| {
        out.push(tag);
        if let Some(len) = length_prefix(form, bytes.len())? {
            out.extend_from_slice(&len.to_le_bytes());
        }
        out.extend_from_slice(bytes);
        Ok(())
    };
    match v {
        Physical::Null => out.push(tags::NULL),
        Physical::Bool(false) => out.push(tags::BOOL_FALSE),
        Physical::Bool(true) => out.push(tags::BOOL_TRUE),
        Physical::Int(i) => write_int(i, out),
        Physical::Float(Float::F32(f)) => {
            out.push(tags::FLOAT32);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        Physical::Float(Float::F64(f)) => {
            out.push(tags::FLOAT64);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        Physical::Text(s) => variable(tags::STRING, s.as_bytes())?,
        Physical::Bytes(b) => variable(tags::BYTES, b)?,
    }
    Ok(())
}

fn write_int(i: Int, out: &mut Vec<u8>) {
    macro_rules! le {
        ($tag:ident, $v:expr) => {{
            out.push(tags::$tag);
            out.extend_from_slice(&$v.to_le_bytes());
        }};
    }
    match i {
        Int::I8(v) => le!(INT8, v),
        Int::I16(v) => le!(INT16, v),
        Int::I32(v) => le!(INT32, v),
        Int::I64(v) => le!(INT64, v),
        Int::I128(v) => le!(INT128, v),
        Int::U8(v) => le!(UINT8, v),
        Int::U16(v) => le!(UINT16, v),
        Int::U32(v) => le!(UINT32, v),
        Int::U64(v) => le!(UINT64, v),
        Int::U128(v) => le!(UINT128, v),
    }
}

/// One scalar as read from the wire.
pub type Scalar<'a> = (Option<Logical>, Physical<'a>);

/// Read one scalar in `form` from the front of `bytes`, validating it.
/// Returns the scalar and how many bytes it occupied.
///
/// # Examples
///
/// In a frame, text carries a length, so the reader stops where the next
/// node starts.
///
/// ```
/// use vitaminc_aead::leaf::{read, write, Form, ScalarError};
/// use vitaminc_aead::plaintext::Physical;
/// use vitaminc_aead::tags;
///
/// let mut frame = Vec::new();
/// write(None, Physical::Text("hi"), Form::Frame, &mut frame)?;
/// let written = frame.len();
/// frame.push(tags::NULL); // the next node
/// let ((ty, value), used) = read(&frame, Form::Frame)?;
/// assert_eq!((ty, value, used), (None, Physical::Text("hi"), written));
/// # Ok::<(), ScalarError>(())
/// ```
pub fn read(bytes: &[u8], form: Form) -> Result<(Scalar<'_>, usize), ScalarError> {
    let mut c = Cursor { buf: bytes, pos: 0 };
    let scalar = read_at(&mut c, form)?;
    Ok((scalar, c.pos))
}

/// Read one sealed leaf's plaintext, which must be exactly one scalar.
pub fn read_leaf(bytes: &[u8]) -> Result<Scalar<'_>, ScalarError> {
    let (scalar, used) = read(bytes, Form::Leaf)?;
    if used != bytes.len() {
        return Err(ScalarError::Malformed);
    }
    Ok(scalar)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8, ScalarError> {
        let b = *self.buf.get(self.pos).ok_or(ScalarError::Malformed)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ScalarError> {
        let end = self.pos.checked_add(n).ok_or(ScalarError::Malformed)?;
        let s = self.buf.get(self.pos..end).ok_or(ScalarError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ScalarError> {
        self.take(N)?.try_into().map_err(|_| ScalarError::Malformed)
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }

    fn variable(&mut self, form: Form) -> Result<&'a [u8], ScalarError> {
        match form {
            Form::Frame => {
                // On a 16-bit target a length above `usize::MAX` cannot
                // fit in any buffer, so it is malformed, not truncated.
                let n = usize::try_from(u32::from_le_bytes(self.fixed()?))
                    .map_err(|_| ScalarError::Malformed)?;
                self.take(n)
            }
            Form::Leaf => Ok(self.rest()),
        }
    }
}

fn read_at<'a>(c: &mut Cursor<'a>, form: Form) -> Result<Scalar<'a>, ScalarError> {
    let tag = c.byte()?;
    if tag == tags::LOGICAL {
        return read_envelope(c, form);
    }
    if let Some(v) = read_physical(tag, c, form)? {
        return Ok((None, v));
    }
    match tag {
        tags::UNDEFINED => Ok((Some(Logical::Undefined), Physical::Null)),
        tags::DATE => read_date(c),
        tags::TIMESTAMP => read_timestamp(c),
        tags::DECIMAL => read_decimal(c),
        _ => Err(ScalarError::Malformed),
    }
}

/// The `0xF3` envelope: a logical type with no shorthand tag, over a
/// physical scalar.
fn read_envelope<'a>(c: &mut Cursor<'a>, form: Form) -> Result<Scalar<'a>, ScalarError> {
    let ty = Logical::from_wire(c.byte()?, c.byte()?).ok_or(ScalarError::Malformed)?;
    let tag = c.byte()?;
    let v = read_physical(tag, c, form)?.ok_or(ScalarError::Malformed)?;
    if has_shorthand(ty) {
        return Err(ScalarError::Malformed);
    }
    if !ty.admits(&v) {
        return Err(ScalarError::Invalid);
    }
    Ok((Some(ty), v))
}

fn read_date<'a>(c: &mut Cursor<'a>) -> Result<Scalar<'a>, ScalarError> {
    let from_ce = i32::from_le_bytes(c.fixed()?);
    let days = from_ce
        .checked_sub(EPOCH_DAYS_FROM_CE)
        .ok_or(ScalarError::Invalid)?;
    let v = Physical::Int(Int::I32(days));
    if !Logical::Date.admits(&v) {
        return Err(ScalarError::Invalid);
    }
    Ok((Some(Logical::Date), v))
}

fn read_timestamp<'a>(c: &mut Cursor<'a>) -> Result<Scalar<'a>, ScalarError> {
    let seconds = i64::from_le_bytes(c.fixed()?);
    let sub = u32::from_le_bytes(c.fixed()?);
    // A leap second (nanos past 999,999,999) has no count.
    if i128::from(sub) >= NANOS_PER_SECOND {
        return Err(ScalarError::Invalid);
    }
    let v = Physical::Int(Int::I128(
        i128::from(seconds) * NANOS_PER_SECOND + i128::from(sub),
    ));
    if !Logical::Timestamp(TimeUnit::Nanos).admits(&v) {
        return Err(ScalarError::Invalid);
    }
    Ok((Some(Logical::Timestamp(TimeUnit::Nanos)), v))
}

fn read_decimal<'a>(c: &mut Cursor<'a>) -> Result<Scalar<'a>, ScalarError> {
    let flags = u32::from_le_bytes(c.fixed()?);
    // The 96-bit magnitude, little-endian `lo`, `mid`, `hi`, widened.
    let mut word = [0u8; 16];
    word[..12].copy_from_slice(&c.fixed::<12>()?);
    let magnitude = i128::from_le_bytes(word);
    if flags & DECIMAL_RESERVED != 0 {
        return Err(ScalarError::Malformed);
    }
    let scale = ((flags & DECIMAL_SCALE_MASK) >> DECIMAL_SCALE_SHIFT) as u8;
    if scale > MAX_DECIMAL_SCALE {
        return Err(ScalarError::Invalid);
    }
    // A negative zero reads as zero: the sign is meaningless and
    // `(scale, mantissa)` has no way to carry it.
    let mantissa = if flags & DECIMAL_SIGN != 0 {
        -magnitude
    } else {
        magnitude
    };
    Ok((
        Some(Logical::Decimal { scale }),
        Physical::Int(Int::I128(mantissa)),
    ))
}

/// `None` for a tag that is not a plain physical scalar.
fn read_physical<'a>(
    tag: u8,
    c: &mut Cursor<'a>,
    form: Form,
) -> Result<Option<Physical<'a>>, ScalarError> {
    if let Some(i) = read_int(tag, c)? {
        return Ok(Some(Physical::Int(i)));
    }
    Ok(Some(match tag {
        tags::NULL => Physical::Null,
        tags::BOOL_FALSE => Physical::Bool(false),
        tags::BOOL_TRUE => Physical::Bool(true),
        // Raw bit patterns, so signalling NaNs survive.
        tags::FLOAT32 => {
            Physical::Float(Float::F32(f32::from_bits(u32::from_le_bytes(c.fixed()?))))
        }
        tags::FLOAT64 => {
            Physical::Float(Float::F64(f64::from_bits(u64::from_le_bytes(c.fixed()?))))
        }
        tags::STRING => Physical::Text(
            core::str::from_utf8(c.variable(form)?).map_err(|_| ScalarError::Malformed)?,
        ),
        tags::BYTES => Physical::Bytes(c.variable(form)?),
        _ => return Ok(None),
    }))
}

/// `None` for a tag that is not an int.
fn read_int(tag: u8, c: &mut Cursor<'_>) -> Result<Option<Int>, ScalarError> {
    Ok(Some(match tag {
        tags::INT8 => Int::I8(i8::from_le_bytes(c.fixed()?)),
        tags::INT16 => Int::I16(i16::from_le_bytes(c.fixed()?)),
        tags::INT32 => Int::I32(i32::from_le_bytes(c.fixed()?)),
        tags::INT64 => Int::I64(i64::from_le_bytes(c.fixed()?)),
        tags::INT128 => Int::I128(i128::from_le_bytes(c.fixed()?)),
        tags::UINT8 => Int::U8(u8::from_le_bytes(c.fixed()?)),
        tags::UINT16 => Int::U16(u16::from_le_bytes(c.fixed()?)),
        tags::UINT32 => Int::U32(u32::from_le_bytes(c.fixed()?)),
        tags::UINT64 => Int::U64(u64::from_le_bytes(c.fixed()?)),
        tags::UINT128 => Int::U128(u128::from_le_bytes(c.fixed()?)),
        _ => return Ok(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::kinds::{MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS};

    fn leaf(ty: Option<Logical>, v: Physical<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        write_leaf(ty, v, &mut out).expect("writes");
        out
    }

    fn frame(ty: Option<Logical>, v: Physical<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        write(ty, v, Form::Frame, &mut out).expect("writes");
        out
    }

    /// Every tag's bytes, pinned. These are the cross-language wire
    /// commitment and must never change.
    #[test]
    fn known_answers() {
        let cases: Vec<(Option<Logical>, Physical<'_>, Vec<u8>)> = vec![
            (None, Physical::Null, vec![0x00]),
            (Some(Logical::Undefined), Physical::Null, vec![0x01]),
            (None, Physical::Bool(false), vec![0x02]),
            (None, Physical::Bool(true), vec![0x03]),
            (
                None,
                Physical::Int(Int::I32(-2)),
                vec![0x04, 0xFE, 0xFF, 0xFF, 0xFF],
            ),
            (
                None,
                Physical::Int(Int::I64(1)),
                vec![0x05, 1, 0, 0, 0, 0, 0, 0, 0],
            ),
            (None, Physical::Int(Int::U32(34)), vec![0x06, 34, 0, 0, 0]),
            (
                None,
                Physical::Int(Int::U64(u64::MAX)),
                vec![0x07, 255, 255, 255, 255, 255, 255, 255, 255],
            ),
            (
                None,
                Physical::Float(Float::F32(1.0)),
                vec![0x08, 0, 0, 0x80, 0x3F],
            ),
            (
                None,
                Physical::Float(Float::F64(-0.0)),
                vec![0x09, 0, 0, 0, 0, 0, 0, 0, 0x80],
            ),
            (None, Physical::Text("hi"), vec![0x0A, b'h', b'i']),
            (None, Physical::Bytes(&[9, 8]), vec![0x0B, 9, 8]),
            (None, Physical::Int(Int::I8(-1)), vec![0x0C, 0xFF]),
            (None, Physical::Int(Int::U8(7)), vec![0x0D, 7]),
            (None, Physical::Int(Int::I16(-2)), vec![0x0E, 0xFE, 0xFF]),
            (None, Physical::Int(Int::U16(258)), vec![0x0F, 2, 1]),
            (
                None,
                Physical::Int(Int::I128(-1)),
                [vec![0x10], vec![0xFF; 16]].concat(),
            ),
            (
                None,
                Physical::Int(Int::U128(1)),
                [vec![0x11, 1], vec![0; 15]].concat(),
            ),
            // 2000-03-01 is 11,017 days after the epoch and 730,180 days from CE.
            (
                Some(Logical::Date),
                Physical::Int(Int::I32(11_017)),
                vec![0x12, 0x44, 0x24, 0x0B, 0x00],
            ),
            // One second and five nanoseconds after the epoch.
            (
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(1_000_000_005)),
                vec![0x13, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0],
            ),
            // 1.50: scale 2 in the flags, mantissa 150.
            (
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I128(150)),
                vec![0x14, 0, 0, 2, 0, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            // -1.5: sign bit set, scale 1, mantissa 15.
            (
                Some(Logical::Decimal { scale: 1 }),
                Physical::Int(Int::I128(-15)),
                vec![0x14, 0, 0, 1, 0x80, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
        ];
        for (ty, v, expected) in cases {
            assert_eq!(leaf(ty, v), expected, "{ty:?} {v:?}");
            assert_eq!(
                read_leaf(&expected).expect("reads"),
                (ty, v),
                "{ty:?} {v:?}"
            );
        }
    }

    #[test]
    fn a_frame_gives_text_and_bytes_a_length() {
        assert_eq!(
            frame(None, Physical::Text("hi")),
            [0x0A, 2, 0, 0, 0, b'h', b'i']
        );
        assert_eq!(frame(None, Physical::Bytes(&[9])), [0x0B, 1, 0, 0, 0, 9]);
        let (scalar, used) = read(&[0x0A, 1, 0, 0, 0, b'x', 0x00], Form::Frame).expect("reads");
        assert_eq!(scalar, (None, Physical::Text("x")));
        assert_eq!(used, 6);
        // In a leaf the payload runs to the end, so the same bytes are a
        // string holding the length prefix too.
        assert_eq!(leaf(None, Physical::Text("hi")), [0x0A, b'h', b'i']);
    }

    #[test]
    fn the_envelope_carries_logical_types_without_a_tag() {
        let id = [0xAB; 16];
        let bytes = leaf(Some(Logical::Uuid), Physical::Bytes(&id));
        assert_eq!(&bytes[..4], [0xF3, 5, 0, 0x0B]);
        assert_eq!(&bytes[4..], id);
        assert_eq!(
            read_leaf(&bytes).expect("reads"),
            (Some(Logical::Uuid), Physical::Bytes(&id))
        );

        let ms = leaf(
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(1_700_000_000_000)),
        );
        assert_eq!(&ms[..4], [0xF3, 3, 1, 0x05]);
        assert_eq!(
            read_leaf(&ms).expect("reads"),
            (
                Some(Logical::Timestamp(TimeUnit::Millis)),
                Physical::Int(Int::I64(1_700_000_000_000))
            )
        );

        // In a frame the physical scalar inside the envelope has its length.
        let f = frame(Some(Logical::Uuid), Physical::Bytes(&id));
        assert_eq!(&f[..8], [0xF3, 5, 0, 0x0B, 16, 0, 0, 0]);
    }

    #[test]
    fn an_unknown_logical_type_is_carried_through() {
        let bytes = [0xF3, 200, 9, 0x06, 34, 0, 0, 0];
        let (ty, v) = read_leaf(&bytes).expect("reads");
        assert!(matches!(ty, Some(Logical::Unknown(u)) if u.id() == 200 && u.param() == 9));
        assert_eq!(v, Physical::Int(Int::U32(34)));
        assert_eq!(leaf(ty, v), bytes);
    }

    #[test]
    fn there_is_one_encoding_per_value() {
        // An envelope where a shorthand tag exists is refused.
        assert_eq!(
            read_leaf(&[0xF3, 2, 0, 0x04, 0, 0, 0, 0]),
            Err(ScalarError::Malformed)
        );
        assert_eq!(read_leaf(&[0xF3, 1, 0, 0x00]), Err(ScalarError::Malformed));
        // Id 0 means "no logical type" and has no envelope.
        assert_eq!(read_leaf(&[0xF3, 0, 0, 0x00]), Err(ScalarError::Malformed));
        // A known id with a parameter it cannot take.
        assert_eq!(read_leaf(&[0xF3, 5, 1, 0x0B]), Err(ScalarError::Malformed));
        // The long envelope is reserved.
        assert_eq!(read_leaf(&[0xF4, 5, 0, 0x0B]), Err(ScalarError::Malformed));
        // The writer never produces an envelope for a shorthand type.
        assert_eq!(leaf(Some(Logical::Undefined), Physical::Null), [0x01]);
    }

    #[test]
    fn invalid_values_are_refused_both_ways() {
        let mut out = Vec::new();
        assert_eq!(
            write_leaf(Some(Logical::Uuid), Physical::Bytes(&[0; 15]), &mut out),
            Err(ScalarError::Invalid)
        );
        assert_eq!(
            write_leaf(Some(Logical::Date), Physical::Text("2000-01-01"), &mut out),
            Err(ScalarError::Invalid)
        );
        assert_eq!(
            write_leaf(
                Some(Logical::Date),
                Physical::Int(Int::I64(i64::from(MAX_DATE_DAYS) + 1)),
                &mut out
            ),
            Err(ScalarError::Invalid)
        );
        assert_eq!(
            read_leaf(&[0xF3, 5, 0, 0x0B, 1, 2, 3]),
            Err(ScalarError::Invalid)
        );
        // A DATE payload past chrono's range.
        assert_eq!(
            read_leaf(&[0x12, 0xFF, 0xFF, 0xFF, 0x7F]),
            Err(ScalarError::Invalid)
        );
        // A leap second.
        assert_eq!(
            read_leaf(&[0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0xCA, 0x9A, 0x3B]),
            Err(ScalarError::Invalid)
        );
        // A decimal with a scale past 28, and one with reserved flag bits.
        assert_eq!(
            read_leaf(&[0x14, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ScalarError::Invalid)
        );
        assert_eq!(
            read_leaf(&[0x14, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ScalarError::Malformed)
        );
        // A timestamp count that is in range in nanoseconds.
        assert!(read_leaf(&leaf(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(MAX_TIMESTAMP_NANOS))
        ))
        .is_ok());
    }

    #[test]
    fn decimal_negative_zero_reads_as_zero() {
        let neg_zero = [0x14, 0, 0, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            read_leaf(&neg_zero).expect("reads"),
            (
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I128(0))
            )
        );
        // And is never written: zero has no sign.
        assert_eq!(
            leaf(
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I128(0))
            )[4],
            0
        );
    }

    #[test]
    fn malformed_leaves_are_refused() {
        assert_eq!(read_leaf(&[]), Err(ScalarError::Malformed));
        assert_eq!(read_leaf(&[0x06, 1, 2]), Err(ScalarError::Malformed));
        assert_eq!(read_leaf(&[0x00, 0x00]), Err(ScalarError::Malformed));
        assert_eq!(read_leaf(&[0x0A, 0xFF]), Err(ScalarError::Malformed));
        assert_eq!(read_leaf(&[0x15]), Err(ScalarError::Malformed));
        assert_eq!(read_leaf(&[0xF0]), Err(ScalarError::Malformed));
        assert_eq!(
            read(&[0x0A, 5, 0, 0, 0, b'x'], Form::Frame),
            Err(ScalarError::Malformed)
        );
    }

    #[test]
    fn a_frame_length_must_fit_in_u32() {
        // A 4 GiB slice can't be built in a test, so the length check is a
        // helper, checked at its edges; `write` calls it before writing.
        assert_eq!(length_prefix(Form::Frame, 0), Ok(Some(0)));
        assert_eq!(
            length_prefix(Form::Frame, u32::MAX as usize),
            Ok(Some(u32::MAX))
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(
                length_prefix(Form::Frame, u32::MAX as usize + 1),
                Err(ScalarError::TooLong)
            );
            // A leaf has no prefix, so no limit.
            assert_eq!(length_prefix(Form::Leaf, u32::MAX as usize + 1), Ok(None));
        }
        let mut out = Vec::new();
        assert!(write(None, Physical::Text(""), Form::Frame, &mut out).is_ok());
        assert_eq!(out, [0x0A, 0, 0, 0, 0]);
    }

    #[test]
    fn the_reserved_decimal_flags_are_every_other_bit() {
        assert_eq!(DECIMAL_RESERVED, !(DECIMAL_SIGN | DECIMAL_SCALE_MASK));
    }

    #[test]
    fn an_invalid_value_writes_nothing() {
        let mut out = vec![0xAB];
        assert_eq!(
            write(
                Some(Logical::Uuid),
                Physical::Bytes(&[0; 15]),
                Form::Frame,
                &mut out
            ),
            Err(ScalarError::Invalid)
        );
        assert_eq!(out, [0xAB]);
    }

    /// The scalar vectors of the cross-language corpus, read by this codec
    /// in frame form and written back. Container vectors (`0xF0`–`0xF2`)
    /// belong to the frame, not the codec.
    #[test]
    fn the_conformance_corpus_round_trips_through_the_codec() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/value-conformance.json"))
                .expect("corpus");
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect()
        };
        let is_scalar = |b: &[u8]| b.first().is_some_and(|t| !(0xF0..=0xF2).contains(t));

        let mut checked = 0;
        for v in corpus["vectors"].as_array().expect("vectors") {
            let name = v["name"].as_str().expect("name");
            let bytes = hex(v["transport"].as_str().expect("transport"));
            if !is_scalar(&bytes) {
                continue;
            }
            let read = read(&bytes, Form::Frame);
            match name {
                // Decided: a leap second has no count, so it is refused.
                "timestamp-leap" => assert_eq!(read, Err(ScalarError::Invalid), "{name}"),
                // Decided: a negative zero reads as zero, written unsigned.
                "decimal-negative-zero" => {
                    let ((ty, value), _) = read.expect(name);
                    assert_eq!(value, Physical::Int(Int::I128(0)), "{name}");
                    let mut out = Vec::new();
                    write(ty, value, Form::Frame, &mut out).expect(name);
                    assert_ne!(out, bytes, "{name}");
                }
                _ => {
                    let ((ty, value), used) = read.expect(name);
                    assert_eq!(used, bytes.len(), "{name}");
                    let mut out = Vec::new();
                    write(ty, value, Form::Frame, &mut out).expect(name);
                    assert_eq!(out, bytes, "{name}");
                }
            }
            checked += 1;
        }
        assert!(checked > 20, "only {checked} scalar vectors");

        for v in corpus["malformed"].as_array().expect("malformed") {
            let name = v["name"].as_str().expect("name");
            let bytes = hex(v["transport"].as_str().expect("transport"));
            if !is_scalar(&bytes) {
                continue;
            }
            // Refused outright, or a valid scalar followed by trailing bytes.
            match read(&bytes, Form::Frame) {
                Err(_) => {}
                Ok((_, used)) => assert!(used < bytes.len(), "{name}"),
            }
        }
    }

    #[test]
    fn the_wire_timestamp_is_seconds_and_nanos() {
        // A negative count splits into floor seconds and a positive remainder.
        let bytes = leaf(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(-1)),
        );
        assert_eq!(
            bytes,
            [0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x9A, 0x3B]
        );
        assert_eq!(
            read_leaf(&bytes).expect("reads"),
            (
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(-1))
            )
        );
    }

    #[cfg(all(feature = "chrono", feature = "rust_decimal"))]
    #[test]
    fn shorthand_payloads_match_the_chrono_and_rust_decimal_layouts() {
        use crate::plaintext::kinds::{chrono as conv, decimal as dec};
        use chrono::{DateTime, Datelike, NaiveDate};
        use rust_decimal::Decimal;

        let date = NaiveDate::from_ymd_opt(1899, 12, 31).expect("date");
        let bytes = leaf(
            Some(Logical::Date),
            Physical::Int(Int::I32(conv::date_days(date))),
        );
        assert_eq!(bytes[1..], date.num_days_from_ce().to_le_bytes());

        let ts = DateTime::from_timestamp(-7, 123_456_789).expect("timestamp");
        let bytes = leaf(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(conv::timestamp_nanos(ts).expect("count"))),
        );
        assert_eq!(bytes[1..9], ts.timestamp().to_le_bytes());
        assert_eq!(bytes[9..], ts.timestamp_subsec_nanos().to_le_bytes());

        for s in [
            "0",
            "-1234.5678",
            "79228162514264337593543950335",
            "-0.0000000000000000000000000001",
        ] {
            let d: Decimal = s.parse().expect("decimal");
            let (scale, mantissa) = dec::parts(d);
            let bytes = leaf(
                Some(Logical::Decimal { scale }),
                Physical::Int(Int::I128(mantissa)),
            );
            assert_eq!(bytes[1..], d.serialize(), "{s}");
            let (ty, v) = read_leaf(&bytes).expect("reads");
            assert_eq!(ty, Some(Logical::Decimal { scale }));
            assert_eq!(v, Physical::Int(Int::I128(mantissa)));
        }
    }

    use quickcheck_macros::quickcheck;

    /// A decimal negative zero: the one decided case that reads back as a
    /// different encoding (zero, written without the sign).
    fn is_negative_zero_decimal(b: &[u8]) -> bool {
        b.len() == 17 && b[0] == tags::DECIMAL && b[4] & 0x80 != 0 && b[5..].iter().all(|&x| x == 0)
    }

    /// Whatever `read` accepts in either form writes back to the bytes it
    /// read, so no value has a second encoding.
    fn reads_then_writes_back(bytes: &[u8]) -> bool {
        [Form::Leaf, Form::Frame]
            .into_iter()
            .all(|form| match read(bytes, form) {
                Err(_) => true,
                Ok(((ty, v), used)) => {
                    let mut out = Vec::new();
                    write(ty, v, form, &mut out).is_ok()
                        && (out == bytes[..used] || is_negative_zero_decimal(&bytes[..used]))
                }
            })
    }

    #[quickcheck]
    fn any_tagged_input_reads_without_panic_and_has_one_encoding(
        tag: u8,
        id: u8,
        param: u8,
        rest: Vec<u8>,
    ) -> bool {
        let tag = tag % 0x15; // the shorthand table, 0x00..=0x14
        let plain = [&[tag][..], &rest[..]].concat();
        let envelope = [&[tags::LOGICAL, id % 8, param % 32, tag][..], &rest[..]].concat();
        reads_then_writes_back(&plain) && reads_then_writes_back(&envelope)
    }

    /// The sign and word of an int scalar, so values compare across the
    /// width the reader returns.
    fn int_value(v: Physical<'_>) -> Option<(bool, u128)> {
        match v {
            Physical::Int(i) => Some(i.sign_and_word()),
            _ => None,
        }
    }

    #[quickcheck]
    fn generated_logical_values_round_trip_and_refuse_every_prefix(n: i64, scale: u8) -> bool {
        let cases = [
            // Within chrono's date range either way.
            (Logical::Date, Int::I64(n % i64::from(MAX_DATE_DAYS))),
            (Logical::Timestamp(TimeUnit::Nanos), Int::I64(n)),
            // Within chrono's range in milliseconds, through the envelope.
            (
                Logical::Timestamp(TimeUnit::Millis),
                Int::I64(n % 8_000_000_000_000_000),
            ),
            (Logical::Decimal { scale: scale % 29 }, Int::I64(n)),
        ];
        cases.into_iter().all(|(ty, int)| {
            [Form::Frame, Form::Leaf].into_iter().all(|form| {
                let mut bytes = Vec::new();
                write(Some(ty), Physical::Int(int), form, &mut bytes).expect("writes");
                let read_back = read(&bytes, form).is_ok_and(|((t, v), used)| {
                    t == Some(ty)
                        && int_value(v) == Some(int.sign_and_word())
                        && used == bytes.len()
                });
                let prefixes_refused = (0..bytes.len()).all(|k| read(&bytes[..k], form).is_err());
                read_back && prefixes_refused
            })
        })
    }

    #[test]
    fn an_envelope_in_a_frame_reads_back_with_its_length() {
        let id = [0xAB; 16];
        let mut f = frame(Some(Logical::Uuid), Physical::Bytes(&id));
        let written = f.len();
        f.push(tags::NULL); // the next node in the frame
        let (scalar, used) = read(&f, Form::Frame).expect("reads");
        assert_eq!(scalar, (Some(Logical::Uuid), Physical::Bytes(&id)));
        assert_eq!(used, written);

        let unknown = Logical::from_wire(200, 9);
        let mut f = frame(unknown, Physical::Text("hi"));
        let written = f.len();
        f.push(tags::NULL);
        let (scalar, used) = read(&f, Form::Frame).expect("reads");
        assert_eq!(scalar, (unknown, Physical::Text("hi")));
        assert_eq!(used, written);
    }

    #[test]
    fn a_shorthand_type_uses_its_tag_at_any_int_width() {
        let date = Some(Logical::Date);
        let wide = leaf(date, Physical::Int(Int::I64(11_017)));
        assert_eq!(wide, leaf(date, Physical::Int(Int::I32(11_017))));
        assert_eq!(
            read_leaf(&wide).expect("reads"),
            (date, Physical::Int(Int::I32(11_017)))
        );

        let ns = Some(Logical::Timestamp(TimeUnit::Nanos));
        assert_eq!(leaf(ns, Physical::Int(Int::U64(5)))[0], tags::TIMESTAMP);

        let dec = Some(Logical::Decimal { scale: 2 });
        let bytes = leaf(dec, Physical::Int(Int::I16(-150)));
        assert_eq!(bytes[0], tags::DECIMAL);
        assert_eq!(
            read_leaf(&bytes).expect("reads"),
            (dec, Physical::Int(Int::I128(-150)))
        );
    }

    #[test]
    fn every_shorthand_type_is_refused_in_an_envelope() {
        let zero = [0u8; 16];
        // Timestamp in nanoseconds (param 3) over INT128.
        let ns = [&[0xF3, 3, 3, 0x10][..], &zero].concat();
        assert_eq!(read_leaf(&ns), Err(ScalarError::Malformed));
        // Decimal with scale 2 over INT128.
        let dec = [&[0xF3, 4, 2, 0x10][..], &zero].concat();
        assert_eq!(read_leaf(&dec), Err(ScalarError::Malformed));
        // Timestamp in milliseconds (param 1) has no shorthand, so the
        // same shape reads.
        let ms = [&[0xF3, 3, 1, 0x10][..], &zero].concat();
        assert!(read_leaf(&ms).is_ok());
    }

    #[test]
    fn an_envelope_holds_only_a_plain_physical_scalar() {
        // Another envelope inside an envelope.
        assert_eq!(
            read_leaf(&[0xF3, 200, 0, 0xF3, 200, 0, 0x00]),
            Err(ScalarError::Malformed)
        );
        // A shorthand tag inside an envelope.
        assert_eq!(
            read_leaf(&[0xF3, 200, 0, 0x01]),
            Err(ScalarError::Malformed)
        );
        assert_eq!(
            read_leaf(&[0xF3, 200, 0, 0x12, 0x44, 0x24, 0x0B, 0x00]),
            Err(ScalarError::Malformed)
        );
        // An unknown tag, and no tag at all.
        assert_eq!(
            read_leaf(&[0xF3, 200, 0, 0x15]),
            Err(ScalarError::Malformed)
        );
        assert_eq!(read_leaf(&[0xF3, 200, 0]), Err(ScalarError::Malformed));
    }

    #[test]
    fn a_date_far_below_the_epoch_is_refused_not_overflowed() {
        // `i32::MIN` days from the common era.
        assert_eq!(
            read_leaf(&[0x12, 0x00, 0x00, 0x00, 0x80]),
            Err(ScalarError::Invalid)
        );
    }

    #[test]
    fn a_leaf_of_only_the_text_or_bytes_tag_is_empty() {
        assert_eq!(read_leaf(&[tags::STRING]), Ok((None, Physical::Text(""))));
        assert_eq!(read_leaf(&[tags::BYTES]), Ok((None, Physical::Bytes(&[]))));
    }

    #[test]
    fn scalar_errors_display_and_are_errors() {
        fn is_error<E: core::error::Error>(_: &E) {}
        is_error(&ScalarError::Malformed);
        assert_eq!(
            ScalarError::Invalid.to_string(),
            "value is not valid for its logical type"
        );
        assert_eq!(
            ScalarError::TooLong.to_string(),
            "text or bytes too long for a u32 length"
        );
        assert_eq!(ScalarError::Malformed.to_string(), "malformed scalar");
    }
}
