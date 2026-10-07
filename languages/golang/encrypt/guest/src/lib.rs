// Security lints — the block `stack-encrypt` and `stack-auth` carry, minus
// `deny(unsafe_code)`: the export surface (`abi`) and the token import
// (`host`) are `extern "C"` over raw pointers by nature. Every `unsafe`
// block is confined to those two wasm32-only modules and documented at the
// site; `unsafe_op_in_unsafe_fn` keeps each one explicit. The allocator,
// the buffer registry and the transport import are `stack-guest-abi`'s.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
// Prevent mem::forget from bypassing ZeroizeOnDrop
#![warn(clippy::mem_forget)]
// Prevent accidental data leaks via output
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// Code quality
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
// Relax in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]
// The crate's target is wasm32; `abi` and `host` only exist there, so on a
// native doc build their intra-doc links have nothing to resolve to. The
// wasm32 doc build (`mise run wasm:guest:test`) is where links are enforced.
#![cfg_attr(not(target_arch = "wasm32"), allow(rustdoc::broken_intra_doc_links))]
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
//! `se_cipher_init`; derived data keys and index keys never leave.
//!
//! The exports are the record path (`se_encrypt_record`, `se_decrypt_record`),
//! per-field term derivation (`se_term`), keyset resolution (`se_keyset`),
//! the generator's two questions (`se_plan_check`, `se_targets`) and the
//! lifetime pair (`se_cipher_init`, `se_shutdown`). There is no whole-value
//! export: the Go SDK seals every value under a declaration (ADR-0007).
//!
//! One instance is one client: `se_cipher_init` runs once per instance and
//! the keysets that client uses are selected per call through the options
//! object ([`options`]), loaded on first use. There is no cipher handle,
//! and nothing for the host to allocate, alias or free — `se_shutdown` is
//! the one lifetime call, and it exists because closing a wasm instance
//! frees linear memory without running Rust destructors.
//!
//! Split into:
//!
//! - [`ops`], [`options`], [`config`], [`response`], [`headers`],
//!   [`status`] — everything that is pure logic over
//!   `StackCipher<K>` / `KeysetCipher<K>` / bytes. Compiles and unit-tests
//!   on the native host target (`cargo test` here, no wasm toolchain
//!   needed) against `stack_kms::FakeDataKeySource`.
//! - [`abi`], [`host`] (wasm32 only) — this guest's export surface and its
//!   token import. The conventions every guest shares — `se_alloc` /
//!   `se_dealloc`, the buffer registry, the packed result encoding, the
//!   status table, the `transport_send` import — are `stack_guest_abi`'s;
//!   [`abi`]'s module docs give this guest's contract on top of them.
//!
//! On wasm32 `vitaminc-encrypt` uses its pure-Rust (RustCrypto `aes-gcm`)
//! backend; the trade-offs are documented there. Values cross the boundary
//! in the vitaminc FFI codec (`vitaminc_aead_value::transport` — an FFI
//! encoding, not a storage format); the leaves inside a ciphertext tree are
//! the *frozen* `SealedValue` byte encoding from Phase 2, so a leaf lifted
//! out of a tree is exactly what a database column holds.

pub mod config;
#[cfg(feature = "deterministic-kms")]
pub mod deterministic;
pub mod headers;
pub mod ops;
pub mod options;
pub mod response;
pub mod status;

// The ABI's packed u64 results embed 32-bit pointers, its bounds checks
// read the wasm linear-memory size, and `host` calls imported functions —
// so these modules only exist on wasm32. A native cdylib build therefore
// exports no se_* symbols at all — failing loudly at symbol lookup —
// instead of exporting a silently wrong ABI (the `ptr << 32` packing would
// truncate a 64-bit pointer).
#[cfg(target_arch = "wasm32")]
pub mod abi;
#[cfg(target_arch = "wasm32")]
pub mod host;
