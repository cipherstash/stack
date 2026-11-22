//! The plaintexts of the `date`, `timestamp`, `numeric` and `json`
//! families.
//!
//! The first three are a calendar date, a UTC instant and a decimal
//! number. These are vitaminc's types, re-exported here. Each is built
//! from jiff's `civil::Date` or `Timestamp`, or rust_decimal's `Decimal`.
//! See [`stack_encrypt::value`] for how they are wiped, and how their
//! equality and order terms treat a decimal's scale and a timestamp's
//! nanoseconds.
//!
//! The plaintext of the `json` family's storage-only type is
//! [`JsonPlaintext`]: a JSON document that is wiped when it is dropped, and
//! is sealed as one ciphertext. See [`stack_encrypt::json::JsonPlaintext`]
//! for the stored format and what the ciphertext reveals.
//!
//! ```
//! use eql_bindings::v4::plaintext::Date;
//!
//! let leap_day = jiff::civil::date(2024, 2, 29);
//! let date = Date::new(leap_day);
//! assert_eq!(date.to_jiff(), leap_day);
//! ```

pub use stack_encrypt::json::{JsonPlaintext, JsonTextError};
pub use stack_encrypt::value::{Date, Decimal, OutOfRange, Timestamp};
