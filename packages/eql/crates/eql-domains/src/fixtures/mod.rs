//! The fixture/test layer of the catalog: the native-scalar vocabulary
//! (`ScalarKind` / `BoundedIntKind`), the `Fixture` value tag + `fixtures!`
//! builder, the per-type `TypeFixtures` records + `FIXTURES` table, and the
//! materialised `*_VALUES` slices. One-way dependency: this module references
//! catalog rows (`crate::INTEGER` …); the catalog never references this module.
//!
//! `#[macro_use]` order matters: `fixture` (which defines `fixtures!`) must be
//! declared before `record` (which invokes it), without `#[macro_export]`.

#[macro_use]
pub(crate) mod fixture;
pub(crate) mod kind;
pub(crate) mod record;
pub(crate) mod values;

pub use fixture::Fixture;
pub use kind::{BoundedIntKind, ScalarKind};
pub use record::{
    kind_for, TypeFixtures, BIGINT_FIXTURES, BOOLEAN_FIXTURES, DATE_FIXTURES, DOUBLE_FIXTURES,
    FIXTURES, INTEGER_FIXTURES, JSON_FIXTURES, NUMERIC_FIXTURES, REAL_FIXTURES, SMALLINT_FIXTURES,
    TEXT_FIXTURES, TIMESTAMP_FIXTURES,
};
pub use values::{BIGINT_VALUES, INTEGER_VALUES, SMALLINT_VALUES, TEXT_VALUES};
