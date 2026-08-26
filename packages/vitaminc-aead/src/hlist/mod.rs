//! HList-based static ciphertext shape (opt-in via the `hlist` feature).
//!
//! # Why a second design?
//!
//! The default [`Cipher`](crate::Cipher) / `AesCipherText` path uses a
//! recursive enum, with a `Vec` per nested container and a
//! `Box<dyn Any + Send>` for passthrough values. This is the right trade-off
//! for wasm32 / JS bindings (dynamic shapes, smaller monomorphisation
//! footprint) and for code paths whose structure is only known at runtime.
//!
//! This module provides a parallel, **statically-shaped** encoding for
//! performance-sensitive native Rust code where:
//!
//! - the ciphertext schema is known at compile time (typically derive-macro
//!   generated `Encrypt` / `Decrypt` impls for fixed structs),
//! - the cost of `Box<dyn Any>` allocation + downcast on every passthrough is
//!   undesirable, or
//! - passthrough must remain typed end-to-end with no runtime fallibility.
//!
//! # Shape
//!
//! Each cipher operation produces a *different* output type. The builder
//! threads them into an [`HList`] so the final container type literally
//! describes the encrypted structure:
//!
//! ```text
//! Map<HCons<Entry<Passthrough<u8>>, HCons<Entry<Encrypted>, HNil>>>
//! //  └── passthrough u8 field         └── encrypted bytes field
//! ```
//!
//! Decryption is destructuring — no shape check, no downcast, no allocation
//! for the structural nodes. The leaf ciphertexts (`Encrypted`, `Absent`)
//! still carry their `LocalCipherText` payload.
//!
//! # Trade-offs
//!
//! - **Single `Cipher::Ok` is impossible**: a separate trait,
//!   [`StaticCipher`], replaces [`Cipher`](crate::Cipher) here. The two trait
//!   hierarchies coexist behind the feature flag.
//! - **Homogeneous `Vec<_>` of varying length is not expressible** in HList
//!   form — `Vec<Encrypted>` of uniform primitives still works, but the
//!   dynamic path's `Vec<AesCipherText>` does not have a direct equivalent.
//! - **Type spellings are large**. A derive macro should generate the
//!   `type FooCiphertext = Map<HCons<...>>` aliases; humans should rarely
//!   write them by hand.

mod cipher;
mod types;

pub use cipher::{StaticCipher, StaticMapBuilder};
pub use types::{Absent, Encrypted, Entry, Map, Passthrough, Seq};

/// The empty HList — terminates an [`HCons`] chain.
pub struct HNil;

/// One cell of an HList: head element `H` plus tail HList `T`.
pub struct HCons<H, T>(pub H, pub T);

/// Marker for types that form a well-formed (terminated) HList.
pub trait HList: sealed::Sealed {}
impl HList for HNil {}
impl<H, T: HList> HList for HCons<H, T> {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::HNil {}
    impl<H, T: super::HList> Sealed for super::HCons<H, T> {}
}

/// Construct an HList literal: `hlist![1, "two", 3.0]`.
#[macro_export]
macro_rules! hlist {
    () => { $crate::hlist::HNil };
    ($head:expr $(, $tail:expr)* $(,)?) => {
        $crate::hlist::HCons($head, $crate::hlist![$($tail),*])
    };
}

/// Destructure an HList: `let hlist_pat![a, b, c] = list;`.
#[macro_export]
macro_rules! hlist_pat {
    () => { $crate::hlist::HNil };
    ($head:pat $(, $tail:pat)* $(,)?) => {
        $crate::hlist::HCons($head, $crate::hlist_pat![$($tail),*])
    };
}
