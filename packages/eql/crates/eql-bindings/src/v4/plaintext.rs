//! The plaintexts of the `date`, `timestamp` and `numeric` families: a
//! calendar date, a UTC instant and a decimal number. These are Stack
//! Encrypt's own types, re-exported here; see [`stack_encrypt::value`] for
//! what they hold, how they are wiped, and how their equality and order
//! terms treat a decimal's scale and a timestamp's nanoseconds.
//!
//! With the `chrono` and `rust_decimal` features each converts to and from
//! chrono's `NaiveDate` and `DateTime<Utc>`, or rust_decimal's `Decimal`.
//!
//! ```
//! use eql_bindings::v4::plaintext::Date;
//!
//! let day = Date::from_days_since_epoch(19_782)?; // 2024-02-29
//! assert_eq!(day.days_since_epoch(), 19_782);
//! # Ok::<(), eql_bindings::v4::plaintext::RangeError>(())
//! ```

pub use stack_encrypt::value::{Date, Decimal, RangeError, Timestamp};
