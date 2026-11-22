//! Plaintexts with no Rust standard type: a calendar date, a UTC instant
//! and a decimal number.
//!
//! These are vitaminc-aead's types, re-exported so a caller needs no
//! dependency on vitaminc of their own. Each one is built from the type the
//! ecosystem offers, and wipes its value when it is dropped:
//!
//! | Type | Built from | Feature | Range |
//! |---|---|---|---|
//! | `Date` | jiff's `civil::Date` | `jiff` | `-009999-01-01` to `9999-12-31` |
//! | `Timestamp` | jiff's `Timestamp` | `jiff` | `-009999-01-02T01:59:59Z` to `9999-12-30T22:00:00.999999999Z` |
//! | `Decimal` | rust_decimal's `Decimal` | `rust_decimal` | scale at most 28, mantissa below 2^96 in magnitude |
//!
//! Both features are on by default. The ranges are jiff's and
//! rust_decimal's. Every language's SDK uses the same ranges, so a value
//! one SDK encrypts, every SDK can decrypt.
//!
//! # Why not jiff's and rust_decimal's types directly
//!
//! A jiff `civil::Date` or `Timestamp`, and a rust_decimal `Decimal`, keep
//! their fields private and are `Copy`. Their bytes cannot be wiped, and a
//! copy leaves no trace. The types here hold the same value as integers
//! and wipe them when dropped ([`Zeroize`](zeroize::Zeroize),
//! [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop)).
//!
//! None of the types is `Copy` or `Clone`. This crate reads a plaintext in
//! place, so one value with a ciphertext and several terms is never
//! copied. `Debug` is redacted, and there is no `Ord` or `Hash`, which
//! would compare plaintext in variable time.
//!
//! The value a type is built from, and the value an accessor returns
//! (`to_jiff`, `to_decimal`), are ordinary jiff and rust_decimal values.
//! The caller looks after those: they are not wiped.
//!
//! # Equality and order
//!
//! The ciphertext keeps the value exactly as given. An equality term and an
//! order term (ORE, OPE or block ORE) are derived from vitaminc's encodings
//! of it, which agree:
//!
//! - a decimal's scale is normalised, so `1.5` and `1.50` have one equality
//!   term and order as equal, while each opens as it was stored;
//! - a timestamp is truncated to the microsecond: the nanoseconds below
//!   it are dropped, never rounded, so two instants in the same microsecond
//!   match under `=` and order as equal, while each opens with its own
//!   nanoseconds. Truncation is floor on the count since the epoch, so it
//!   moves an instant before 1970 earlier too. It does not depend on any one
//!   store's rounding;
//! - a date is its day.

/// A calendar date with no time of day and no time zone.
///
/// ```
/// use stack_encrypt::value::Date;
///
/// let leap_day = jiff::civil::date(2024, 2, 29);
/// let date = Date::new(leap_day);
/// assert_eq!(date.to_jiff(), leap_day);
/// ```
#[cfg(feature = "jiff")]
pub use vitaminc_aead::Date;

/// A UTC instant.
///
/// ```
/// use stack_encrypt::value::Timestamp;
///
/// let instant = jiff::Timestamp::new(1_700_000_000, 123_456_789)?;
/// let timestamp = Timestamp::new(instant)?;
/// assert_eq!(timestamp.to_jiff(), instant);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "jiff")]
pub use vitaminc_aead::Timestamp;

/// Why a jiff `Timestamp` could not become a [`Timestamp`].
#[cfg(feature = "jiff")]
pub use vitaminc_aead::OutOfRange;

/// A decimal number: a mantissa and a scale.
///
/// ```
/// use stack_encrypt::value::Decimal;
///
/// let price = rust_decimal::Decimal::new(1999, 2); // 19.99
/// let decimal = Decimal::new(price);
/// assert_eq!(decimal.to_decimal(), price);
/// ```
#[cfg(feature = "rust_decimal")]
pub use vitaminc_aead::Decimal;
