//! `#[derive(Encrypt)]` and `#[derive(Decrypt)]`: how a plaintext value is
//! walked into a sink, and the sink that builds it back.
//!
//! The record derives in the rest of this crate describe a stored record
//! and read `#[stash(...)]` attributes. These two describe a plaintext
//! value and read `#[aead(...)]` attributes. Keeping the two names apart
//! means that one type can derive from both families, and neither family
//! refuses the other's attributes.
//!
//! The generated code names every item through `<crate>::__derive`. That
//! module of `stack_encrypt` is hidden, and contains exactly the items that
//! the expansion uses. `<crate>` is `::stack_encrypt` unless
//! `#[aead(crate = "...")]` names another path to it.

// The files of this module are under the MIT licence in `LICENSE-MIT`
// beside them.

pub(crate) mod attrs;
pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod shape;
#[cfg(test)]
mod test_support;
