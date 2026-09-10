#![deny(unsafe_op_in_unsafe_fn)]
//! # stack-encrypt WASI guest
//!
//! WASI guest module exposing [`stack-encrypt`](stack_encrypt) —
//! ZeroKMS-backed AEAD over structured values, SEM index terms, batched
//! records — to non-Rust hosts. Built for `wasm32-wasip1` and embedded by
//! the Go module in the parent directory (wazero host, `CGO_ENABLED=0`).
//! Phase 3 of `docs/plans/stack-encrypt-go-bindings.md`.
//!
//! Control stays in Rust: request assembly, key derivation, batching, and
//! AAD/PRF context binding run unmodified inside the guest. The host
//! provides exactly two imports (HTTP transport and the bearer token — see
//! [`host`]); what crosses the boundary per call is a value tree in, a
//! ciphertext/record tree out, and — inside the call — the same bytes that
//! would cross TLS anyway. The client key enters guest memory once at
//! `se_cipher_init`; derived data keys and the index key never leave.
//!
//! Split into:
//!
//! - [`ops`], [`context`], [`config`], [`response`], [`headers`], [`status`],
//!   [`sessions`] — everything that is pure logic over `StackCipher<K>` /
//!   bytes. Compiles and unit-tests on the native host target (`cargo
//!   test` here, no wasm toolchain needed) against
//!   `stack_kms::FakeDataKeySource`.
//! - [`abi`], [`host`], [`buffers`] (wasm32 only) — the export surface,
//!   the two host imports, and the buffer registry. See [`abi`]'s module
//!   docs for the full ABI contract.
//!
//! On wasm32 `vitaminc-encrypt` uses its pure-Rust (RustCrypto `aes-gcm`)
//! backend; the trade-offs are documented there. Values cross the boundary
//! in the vitaminc FFI codec (`vitaminc_aead_value::transport` — an FFI
//! encoding, not a storage format); the leaves inside a ciphertext tree are
//! the *frozen* `SealedValue` byte encoding from Phase 2, so a leaf lifted
//! out of a tree is exactly what a database column holds.

pub mod config;
pub mod context;
pub mod headers;
pub mod ops;
pub mod response;
pub mod status;

// Only the wasm32 ABI constructs the table; natively it exists for its
// unit tests.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) mod sessions;

// The ABI's packed u64 results embed 32-bit pointers, its bounds checks
// read the wasm linear-memory size, and `host` calls imported functions —
// so these modules only exist on wasm32. A native cdylib build therefore
// exports no se_* symbols at all — failing loudly at symbol lookup —
// instead of exporting a silently wrong ABI (the `ptr << 32` packing would
// truncate a 64-bit pointer).
#[cfg(target_arch = "wasm32")]
pub mod abi;
// Target-independent (plain `Vec`s and raw pointers, no linear-memory
// reads), so like `sessions` it exists natively for its unit tests — the
// empty-buffer accounting in particular is pinned there.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) mod buffers;
#[cfg(target_arch = "wasm32")]
pub mod host;
