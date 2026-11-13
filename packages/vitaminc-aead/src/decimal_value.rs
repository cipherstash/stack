//! [`Decimal`]: a decimal number that is wiped when dropped.

use vitaminc_protected::{Choice, OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::plaintext::kinds::{decimal as conv, MAX_DECIMAL_SCALE};
use crate::plaintext::{depth, Encrypt, FixedType, Int, Logical, Physical, Scalar, Sink, Width};
use crate::typed::FromScalar;

/// A decimal number, held as its mantissa and scale and wiped when it is
/// dropped: the value is `mantissa × 10^-scale`.
///
/// It encrypts to the same leaf as [`rust_decimal::Decimal`], owned or
/// borrowed, scale included, so `1.50` stays `1.50` and a
/// `rust_decimal::Decimal` field can become a `Decimal` without changing
/// its ciphertext. Every `rust_decimal::Decimal` is one, so building it
/// cannot fail.
///
/// ```
/// use std::str::FromStr;
/// use vitaminc_aead::Decimal;
///
/// let price = rust_decimal::Decimal::from_str("1.50").expect("a decimal");
/// let held = Decimal::new(price);
/// assert_eq!(held.to_decimal().to_string(), "1.50");
///
/// // Equal as numbers, as `rust_decimal` compares them.
/// let one_five = rust_decimal::Decimal::from_str("1.5").expect("a decimal");
/// assert!(held == Decimal::new(one_five));
/// ```
///
/// A `Decimal` is plaintext, so it is handled as the data model's other
/// scalars are: a `rust_decimal::Decimal` is `Copy` and is never wiped.
/// Equality compares the values, as `rust_decimal` does, so `1.5` equals
/// `1.50`; it normalizes both in constant time first (see
/// [`TimingSafeEq`]). It is not `Copy` or `Clone`, and it has no ordering
/// or hash. `Debug` is redacted. `Default` is zero, as for
/// `rust_decimal::Decimal`.
#[derive(Default, OpaqueDebug, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(docsrs, doc(cfg(feature = "rust_decimal")))]
pub struct Decimal {
    /// The mantissa: below 2^96 in magnitude.
    mantissa: i128,
    /// The scale: at most 28.
    scale: u8,
}

impl Decimal {
    /// The number, scale included.
    pub fn new(decimal: rust_decimal::Decimal) -> Self {
        let (scale, mantissa) = conv::parts(decimal);
        Self { mantissa, scale }
    }

    /// The number, as a `rust_decimal::Decimal`. The copy is the caller's
    /// to look after: it cannot be wiped.
    pub fn to_decimal(&self) -> rust_decimal::Decimal {
        // A `Decimal` is only built from a `rust_decimal::Decimal`, whose
        // parts always make one again, so the fallback is never taken.
        conv::decimal(self.scale, Int::I128(self.mantissa)).unwrap_or_default()
    }

    /// The value with trailing zeros taken off the mantissa, as its sign,
    /// its magnitude in three 32-bit limbs and its scale. Constant time:
    /// every value takes the same 28 steps, each a division by ten of the
    /// three limbs and a masked choice.
    fn normalized(&self) -> (Choice, [u32; 3], u8) {
        let negative = Choice::from((self.mantissa >> 127) as u8 & 1);
        let sign = (self.mantissa >> 127) as u128;
        let magnitude = ((self.mantissa as u128) ^ sign).wrapping_sub(sign);
        let mut limbs = [
            magnitude as u32,
            (magnitude >> 32) as u32,
            (magnitude >> 64) as u32,
        ];
        let mut scale = self.scale;
        for _ in 0..MAX_DECIMAL_SCALE {
            let (quotient, remainder) = div10(limbs);
            let strip = remainder.ts_eq(&0) & !scale.ts_eq(&0);
            for (limb, q) in limbs.iter_mut().zip(quotient) {
                *limb = select_u32(*limb, q, strip);
            }
            scale = select_u8(scale, scale.wrapping_sub(1), strip);
        }
        (negative, limbs, scale)
    }
}

/// Three little-endian 32-bit limbs divided by ten, and the remainder.
fn div10(limbs: [u32; 3]) -> ([u32; 3], u32) {
    let mut quotient = [0u32; 3];
    let mut remainder = 0u64;
    for i in (0..3).rev() {
        let current = (remainder << 32) | u64::from(limbs[i]);
        quotient[i] = (current / 10) as u32;
        remainder = current % 10;
    }
    (quotient, remainder as u32)
}

fn select_u32(a: u32, b: u32, choose_b: Choice) -> u32 {
    let mask = u32::from(choose_b.unwrap_u8()).wrapping_neg();
    (a & !mask) | (b & mask)
}

fn select_u8(a: u8, b: u8, choose_b: Choice) -> u8 {
    let mask = choose_b.unwrap_u8().wrapping_neg();
    (a & !mask) | (b & mask)
}

/// Equal as numbers: `1.5` equals `1.50`, as `rust_decimal` has it.
impl TimingSafeEq for Decimal {
    fn ts_eq(&self, other: &Self) -> Choice {
        let (a_negative, a_limbs, a_scale) = self.normalized();
        let (b_negative, b_limbs, b_scale) = other.normalized();
        let mut equal =
            a_negative.unwrap_u8().ts_eq(&b_negative.unwrap_u8()) & a_scale.ts_eq(&b_scale);
        for (a, b) in a_limbs.iter().zip(&b_limbs) {
            equal &= a.ts_eq(b);
        }
        equal
    }
}

impl PartialEq for Decimal {
    fn eq(&self, other: &Self) -> bool {
        self.ts_eq(other).into()
    }
}

impl Eq for Decimal {}

impl From<rust_decimal::Decimal> for Decimal {
    fn from(decimal: rust_decimal::Decimal) -> Self {
        Self::new(decimal)
    }
}

impl From<Decimal> for rust_decimal::Decimal {
    fn from(decimal: Decimal) -> Self {
        decimal.to_decimal()
    }
}

/// The same leaf as `rust_decimal::Decimal`: the mantissa under its scale.
impl Encrypt for Decimal {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = <&Decimal as Encrypt>::FIXED;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

impl Encrypt for &Decimal {
    const DEPTH: Option<usize> = depth::SCALAR;
    /// Every scale shares the one typed null, as for `rust_decimal`.
    const FIXED: Option<FixedType> =
        FixedType::new(Some(Logical::Decimal { scale: 0 }), Width::I128);
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(
            Some(Logical::Decimal { scale: self.scale }),
            Physical::Int(Int::I128(self.mantissa)),
        )
    }
}

impl Scalar for Decimal {}
impl Scalar for &Decimal {}
const _: () = assert!(depth::is_scalar(<Decimal as Encrypt>::DEPTH));

impl FromScalar for Decimal {
    const EXPECTED: &'static str = "decimal";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        rust_decimal::Decimal::from_scalar(ty, value).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::to_frame;
    use vitaminc_protected::Controlled;

    fn frame<P: Encrypt>(value: P) -> Vec<u8> {
        to_frame(value).expect("frames").risky_ref().to_vec()
    }

    fn dec(text: &str) -> rust_decimal::Decimal {
        rust_decimal::Decimal::from_str(text).expect("a decimal")
    }

    /// It walks as the `rust_decimal::Decimal` it holds, scale and all.
    #[test]
    fn it_walks_as_the_decimal_it_holds() {
        let mut negative_zero = rust_decimal::Decimal::new(0, 2);
        negative_zero.set_sign_negative(true);
        for value in [
            dec("0"),
            dec("1.50"),
            dec("-1234.5678"),
            rust_decimal::Decimal::MAX,
            rust_decimal::Decimal::MIN,
            rust_decimal::Decimal::new(1, 28),
            negative_zero,
        ] {
            let held = Decimal::new(value);
            assert_eq!(held.to_decimal(), value, "{value}");
            assert_eq!(held.to_decimal().scale(), value.scale(), "{value}");
            assert_eq!(frame(&held), frame(value), "{value}");
            assert_eq!(frame(Decimal::new(value)), frame(value), "{value}");
        }
        assert_eq!(
            <Decimal as Encrypt>::FIXED,
            <rust_decimal::Decimal as Encrypt>::FIXED
        );
        assert_eq!(Decimal::default().to_decimal(), rust_decimal::Decimal::ZERO);
        let decoded = Decimal::from_scalar(
            Some(Logical::Decimal { scale: 2 }),
            Physical::Int(Int::I128(150)),
        )
        .expect("a decimal");
        assert_eq!(decoded.to_decimal().to_string(), "1.50");
    }

    /// Equality is `rust_decimal`'s, value against value, over scales,
    /// signs, zeros and the extremes.
    #[test]
    fn it_compares_as_rust_decimal_does() {
        let values = [
            "0",
            "0.0",
            "-0.00",
            "1",
            "1.0",
            "1.50",
            "1.5",
            "-1.5",
            "-1.50",
            "10",
            "10.0",
            "100",
            "0.1",
            "0.10",
            "0.01",
            "12345678901234567890.123456789",
            "12345678901234567890.1234567890",
        ];
        let mut all: Vec<rust_decimal::Decimal> = values.iter().map(|v| dec(v)).collect();
        all.extend([
            rust_decimal::Decimal::MAX,
            rust_decimal::Decimal::MIN,
            rust_decimal::Decimal::new(1, 28),
            rust_decimal::Decimal::new(10_i64.pow(18), 28),
            rust_decimal::Decimal::from_i128_with_scale((1 << 96) - 1, 28),
            rust_decimal::Decimal::from_i128_with_scale((1 << 96) - 1, 0),
        ]);
        for a in &all {
            for b in &all {
                assert_eq!(Decimal::new(*a) == Decimal::new(*b), a == b, "{a} and {b}");
            }
        }
    }

    #[test]
    fn it_wipes_and_redacts() {
        let mut held = Decimal::new(dec("123.45"));
        held.zeroize();
        assert!(held == Decimal::default());
        assert!(!format!("{:?}", Decimal::new(dec("123.45"))).contains("123"));
    }
}
