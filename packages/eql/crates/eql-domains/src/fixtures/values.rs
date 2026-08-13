//! Compile-time materialisers: each `*_VALUES` const is a typed `&'static`
//! slice derived from its `TypeFixtures` record (`int_values!` / `text_values!`),
//! the single-sourced plaintext list the SQLx matrix reads and the fixture
//! generator encrypts. No committed generated `.rs` round-trip.

use super::fixture::Fixture;
use super::record::{
    TypeFixtures, BIGINT_FIXTURES, INTEGER_FIXTURES, SMALLINT_FIXTURES, TEXT_FIXTURES,
};

/// Materialise an integer record's fixtures into a typed `&'static` slice at
/// compile time. Integer kinds only: a non-numeric fixture is a const-eval
/// error, mirroring `numeric_value`'s `None`.
macro_rules! int_values {
    ($name:ident, $ty:ty, $rec:expr) => {
        #[doc = concat!("Distinct plaintext fixture values for `", stringify!($rec), "`, ")]
        #[doc = "materialised from its `TypeFixtures` record (see `int_values!`)."]
        pub const $name: &[$ty] = {
            const REC: TypeFixtures = $rec;
            const N: usize = REC.values.len();
            const ARR: [$ty; N] = {
                let mut out = [0 as $ty; N];
                let mut i = 0;
                while i < N {
                    out[i] = match REC.values[i].numeric_value(REC.kind) {
                        Some(v) => {
                            if v < <$ty>::MIN as i128 || v > <$ty>::MAX as i128 {
                                panic!(concat!(
                                    "integer scalar fixture value out of range for `",
                                    stringify!($ty),
                                    "`"
                                ));
                            }
                            v as $ty
                        }
                        None => panic!("integer scalar fixture must resolve to a number"),
                    };
                    i += 1;
                }
                out
            };
            &ARR
        };
    };
}

int_values!(INTEGER_VALUES, i32, INTEGER_FIXTURES);
int_values!(SMALLINT_VALUES, i16, SMALLINT_FIXTURES);
int_values!(BIGINT_VALUES, i64, BIGINT_FIXTURES);

/// Materialise a `text` record's fixtures into a `&'static [&'static str]` at
/// compile time. A non-text fixture is a const-eval panic.
macro_rules! text_values {
    ($name:ident, $rec:expr) => {
        #[doc = concat!("Distinct plaintext fixture values for `", stringify!($rec), "`, ")]
        #[doc = "materialised from its `TypeFixtures` record (see `text_values!`)."]
        pub const $name: &[&'static str] = {
            const REC: TypeFixtures = $rec;
            const N: usize = REC.values.len();
            const ARR: [&'static str; N] = {
                let mut out = [""; N];
                let mut i = 0;
                while i < N {
                    out[i] = match REC.values[i] {
                        Fixture::Text(s) => s,
                        _ => panic!("text scalar fixture must be Fixture::Text"),
                    };
                    i += 1;
                }
                out
            };
            &ARR
        };
    };
}

text_values!(TEXT_VALUES, TEXT_FIXTURES);
