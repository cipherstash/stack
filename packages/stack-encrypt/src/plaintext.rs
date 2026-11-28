//! The items that a hand-written [`Encrypt`](trait@crate::Encrypt) or
//! [`Decrypt`](trait@crate::Decrypt) impl names.
//!
//! Most types derive both traits, with
//! `#[derive(stack_encrypt::Encrypt, stack_encrypt::Decrypt)]`. Write the
//! impls by hand when the derive does not describe the value as you want.
//! For example, a struct with a named field derives as a map, and you want
//! it stored as the one value it holds.
//!
//! A hand-written `Encrypt` impl describes the value to a [`Sink`]: one
//! scalar with [`Sink::scalar`], or a container with [`Sink::seq`] or
//! [`Sink::map`]. Its `DEPTH` says how deeply a value of the type nests, and
//! [`depth`] has the constants for it. A type that encrypts as one value
//! also implements [`Scalar`](crate::Scalar), so that
//! [`KeysetCipher::encrypt`](crate::KeysetCipher::encrypt) takes it.
//!
//! A type that is built from one scalar implements
//! [`FromScalar`](crate::FromScalar). The type then has `Decrypt` with no
//! other code.
//!
//! ```
//! use stack_encrypt::plaintext::{depth, FixedType, Logical, Physical, Sink};
//! use stack_encrypt::{Encrypt, EncryptRef, FromScalar, Scalar, StackCipher};
//! use zeroize::Zeroize;
//!
//! /// An amount in cents. The derive would store it as a map with one
//! /// entry, `cents`. These impls store it as its one integer instead.
//! #[derive(Zeroize)]
//! struct Price {
//!     cents: i64,
//! }
//!
//! impl Encrypt for Price {
//!     const DEPTH: Option<usize> = depth::SCALAR;
//!     const FIXED: Option<FixedType> = <i64 as Encrypt>::FIXED;
//!     fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
//!         self.cents.visit(sink)
//!     }
//! }
//!
//! // `keyset.encrypt` reads the value through a borrow, so the borrow
//! // encrypts too, and is marked `Scalar`.
//! impl Encrypt for &Price {
//!     const DEPTH: Option<usize> = depth::SCALAR;
//!     const FIXED: Option<FixedType> = <&i64 as Encrypt>::FIXED;
//!     fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
//!         self.cents.visit_ref(sink)
//!     }
//! }
//! impl Scalar for Price {}
//! impl Scalar for &Price {}
//!
//! // `FromScalar` gives `Price` its `Decrypt`.
//! impl FromScalar for Price {
//!     const EXPECTED: &'static str = "a price in cents";
//!     const FIXED: Option<FixedType> = <i64 as FromScalar>::FIXED;
//!     fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
//!         i64::from_scalar(ty, value).map(|cents| Price { cents })
//!     }
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let stored = keyset.encrypt(Price { cents: 1999 }).await?;
//! // The stored value is one integer, so it also decrypts as an `i64`.
//! let cents: i64 = keyset.decrypt(stored.clone()).await?;
//! assert_eq!(cents, 1999);
//! let price: Price = keyset.decrypt(stored).await?;
//! assert_eq!(price.cents, 1999);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```

pub use vitaminc_aead::plaintext::{
    FixedType, Float, Int, Logical, MapSink, Physical, SeqSink, Sink, TimeUnit, Width,
};

/// How deeply a type nests, for [`Encrypt::DEPTH`](crate::Encrypt::DEPTH).
///
/// A depth counts the containers below a value's own root. A scalar is `0`,
/// and a sequence or a map is one more than its deepest child. `None` means
/// that the type alone does not fix the depth, as for a recursive type. The
/// encrypting walk then checks each value instead.
///
/// The functions are `const fn`s, so that a type's depth is worked out at
/// compile time from its fields' depths. `#[derive(Encrypt)]` uses them,
/// and fails to compile a type that nests too deeply to be encrypted.
pub mod depth {
    pub use vitaminc_aead::frame::MAX_DEPTH;
    pub use vitaminc_aead::plaintext::depth::{
        container, is_scalar, max, passthrough, within_limit, SCALAR,
    };
}
