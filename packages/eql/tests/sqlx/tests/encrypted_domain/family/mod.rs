//! Family-level tests: invariants that apply across every scalar type in
//! the encrypted-domain family (not integer-specific).

pub mod inlinability;
pub mod jsonb_check;
pub mod jsonb_operator_surface;
pub mod mutations;
pub mod sem;
pub mod support;
