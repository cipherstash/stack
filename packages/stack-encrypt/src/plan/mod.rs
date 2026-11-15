//! What a plan that is data shares with the rest of the crate: the errors a
//! plan is refused with ([`PlanError`]), and the label a plan's context is
//! written as ([`IntoLabel`]).
//!
//! A program does not build a plan in Rust. A record with static types
//! derives `EncryptTarget` and `DecryptSource`, and queries a field through
//! its marker ([`Marker`](crate::Marker)). A program whose declaration is
//! data parses a plan with the `dynamic` feature
//! (`dynamic::record::plan`) and runs it as a `dynamic::Planned` value.
mod error;
mod label;
#[cfg(feature = "dynamic")]
mod values;

pub use error::PlanError;
pub use label::IntoLabel;
#[cfg(feature = "dynamic")]
pub(crate) use label::{field_label, join, FROM_CALL, FROM_PLAN};
#[cfg(feature = "dynamic")]
pub(crate) use values::{FieldValues, Slot};
