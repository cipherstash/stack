#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! Key vendor backends for Stack Encrypt (ADR-0009, ADR-0010, ADR-0011).
//!
//! A **key vendor backend** is a key backend that is not ZeroKMS: AWS KMS,
//! Azure Key Vault, HashiCorp Vault Transit, Google Cloud KMS, or a static
//! key. This crate holds what every vendor shares, so that a vendor crate
//! implements one small trait and nothing else:
//!
//! * [`KeyVendorBackend`]: the vendor seam. A vendor wraps and unwraps a
//!   key under its vendor key, with associated data. That is all.
//! * [`KeysetRecord`]: the customer-held description of a keyset in a key
//!   vendor backend. It is an opaque, versioned string that the customer
//!   keeps in config or in an environment variable.
//! * [`VendorKeySource`]: the adapter that turns one vendor and its keyset
//!   records into a [`DataKeySource`](stack_kms::DataKeySource) and an
//!   [`IndexKeySource`](stack_kms::IndexKeySource), in either key mode.
//!   Vendor crates never implement the stack-kms traits themselves.
//! * [`KeyRouter`]: ZeroKMS and at most one key vendor backend in one key
//!   source, routed by keyset.
//! * [`StaticKeyVendor`]: the static key backend, for development or for
//!   customers who manage the key themselves. Derived data keys only.
//! * [`run_batch`]: N vendor calls with a concurrency limit, backoff on
//!   [`Throttled`](stack_kms::BackendErrorKind::Throttled), and
//!   fail-whole-batch.
//! * [`VendorTransport`]: the HTTP seam a vendor client sends through, of
//!   the same shape as [`ZeroKMSConnection`](stack_kms::ZeroKMSConnection),
//!   so the same vendor code runs on native Rust and in the WASI guest.
//!
//! # The two key modes
//!
//! * **Wrapped data key** ([`KeyMode::Wrapped`](stack_kms::KeyMode::Wrapped)):
//!   each value has its own data key, generated and wrapped by the vendor
//!   key and stored in the leaf's tag. The keyset record holds the wrapped
//!   index key, and the cipher unwraps it inside each settle that needs it.
//!   No key outlives one settle.
//! * **Derived data key** ([`KeyMode::Derived`](stack_kms::KeyMode::Derived)):
//!   the keyset record holds the wrapped root key. The adapter unwraps it
//!   and keeps it for a TTL ([`DEFAULT_ROOT_KEY_TTL`]). Each data key is
//!   `HKDF-SHA256(root key, salt = iv, info = keyset id ‖ descriptor)`, and
//!   the index key is derived from the root key under a separate label.
//!
//! See [`derive`](mod@derive) for the exact derivations and associated data.

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::mem_forget)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]

mod batch;
pub mod derive;
mod error;
mod record;
mod router;
mod source;
mod static_key;
mod transport;
mod vendor;

#[cfg(feature = "test-support")]
pub mod contract;
#[cfg(feature = "test-support")]
mod fake;

pub use batch::{run_batch, BatchOptions};
pub use error::RecordError;
pub use record::{KeysetRecord, RECORD_FORMAT_VERSION, RECORD_PREFIX};
pub use router::KeyRouter;
pub use source::{VendorKeySource, DEFAULT_ROOT_KEY_TTL};
pub use static_key::StaticKeyVendor;
pub use transport::{
    classify_status, TransportError, VendorRequest, VendorResponse, VendorTransport,
};
pub use vendor::{KeyBytes, KeyVendorBackend};

#[cfg(feature = "test-support")]
pub use fake::{FakeVendor, FakeVendorCalls};
