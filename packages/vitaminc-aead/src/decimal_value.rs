//! [`Decimal`]: a decimal number that is wiped when dropped.

use vitaminc_protected::{Choice, OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::plaintext::kinds::{decimal as conv, strip_trailing_zeros};
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

    /// The value as its sign (0, or 0xFF when negative), its significand with every trailing zero
    /// taken off, and the power of ten that scales it: `1.50` and `1.5` are
    /// both `(+, 15, -1)`. Constant time, through
    /// [`strip_trailing_zeros`]: fixed steps, masks, no branch and no
    /// division. The caller wipes what it returns.
    fn canonical(&self) -> (u8, u128, i32) {
        let sign = self.mantissa >> 127;
        let mut magnitude = ((self.mantissa ^ sign).wrapping_sub(sign)) as u128;
        let (significand, trailing) = strip_trailing_zeros(magnitude);
        magnitude.zeroize();
        (
            sign as u8,
            significand,
            trailing.wrapping_sub(i32::from(self.scale)),
        )
    }
}

/// Equal as numbers: `1.5` equals `1.50`, as `rust_decimal` has it. Two
/// zeros are equal whatever their scales.
impl TimingSafeEq for Decimal {
    fn ts_eq(&self, other: &Self) -> Choice {
        let (a_negative, mut a, a_exponent) = self.canonical();
        let (b_negative, mut b, b_exponent) = other.canonical();
        let both_zero = a.ts_eq(&0) & b.ts_eq(&0);
        let same = a_negative.ts_eq(&b_negative) & a.ts_eq(&b) & a_exponent.ts_eq(&b_exponent);
        a.zeroize();
        b.zeroize();
        both_zero | same
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
            assert_eq!(rust_decimal::Decimal::from(Decimal::from(value)), value);
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
            // Values that differ only above the low 32 or 64 bits.
            rust_decimal::Decimal::from_i128_with_scale(1 << 32, 0),
            rust_decimal::Decimal::from_i128_with_scale(1 << 33, 0),
            rust_decimal::Decimal::from_i128_with_scale(1 << 64, 0),
            rust_decimal::Decimal::from_i128_with_scale(1 << 65, 0),
            rust_decimal::Decimal::from_i128_with_scale(10 << 64, 1),
            rust_decimal::Decimal::from_i128_with_scale(-(1 << 64), 0),
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
