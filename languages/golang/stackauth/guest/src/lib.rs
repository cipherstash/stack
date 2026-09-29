// Security lints — the block `stack-encrypt` and `stack-auth` carry, minus
// `deny(unsafe_code)`: the export surface (`abi`) is `extern "C"` over raw
// pointers by nature. Every `unsafe` block is confined to that wasm32-only
// module and documented at the site; `unsafe_op_in_unsafe_fn` keeps each
// one explicit. The allocator, the buffer registry and the input
// validation are `stack-guest-abi`'s.
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
// The crate's target is wasm32; `abi` only exists there, so on a native doc
// build its intra-doc links have nothing to resolve to. The wasm32 doc
// build (`mise run wasm:auth-guest:test`) is where links are enforced.
#![cfg_attr(not(target_arch = "wasm32"), allow(rustdoc::broken_intra_doc_links))]
//! # The credential guest
//!
//! WASI guest module exposing the developer profile —
//! [`stack_profile::ProfileStore`] over one mounted directory — to non-Rust
//! hosts. Built for `wasm32-wasip1` and embedded by the Go package
//! `stackauth` in the parent directory (wazero host, `CGO_ENABLED=0`).
//! ADR-0005 in `packages/stack-encrypt/docs/adr` is the decision this
//! module implements; `docs/plans/stack-encrypt-go-bindings.md` sequences
//! it.
//!
//! # What the host gives it, and what it does not
//!
//! wazero mounts exactly one directory into this module — the profile
//! root, at [`abi`]'s fixed guest path — and gives it **no environment**.
//! The Go side resolves `CS_CONFIG_PATH` and the home directory the way
//! [`ProfileStore::resolve`](stack_profile::ProfileStore::resolve) does,
//! mounts the result, and names the store's directory explicitly on every
//! call. Nothing here reads a variable, and nothing here can name a path
//! the mount does not contain: every path is built by `stack-profile` from
//! a store directory and a validated filename or workspace id.
//!
//! The crypto guest (`bindings/go/stackencrypt/guest`) is unchanged by
//! this one existing. It has no filesystem and no environment, and it
//! handles plaintext and data keys; this module can reach one directory of
//! credentials. The split is what makes both of those true at once.
//!
//! # What crosses the boundary
//!
//! Profile inputs are UTF-8 strings: the store directory (a guest path under
//! the mount), a workspace id, a filename. Outputs are either a UTF-8 string
//! (an id, a path) or a value in vitaminc's FFI codec
//! (`vitaminc_aead_value::transport`): a list of ids, or the fields of
//! `secretkey.json`, `auth.json` or `device.json` as an object. The client
//! key in `secretkey.json` crosses as the text the file holds; the Go side
//! wraps it in its opaque `ClientKey` and wipes its transport copy. A
//! refresh token never crosses: the auth strategy retains it inside this
//! module, while the Go host supplies HTTP through a single transport
//! import. The host can provide an access key or an OIDC provider callback.
//!
//! # Locking
//!
//! WASI preview 1 has no file locking, so this module takes none. The Go
//! side takes the same lock the Rust CLI takes, on the path
//! [`ProfileStore::lock_path`](stack_profile::ProfileStore::lock_path)
//! names (exported here), around the entire device-session refresh export.
//! A fresh token is read without that lock. The refresh export re-reads
//! auth.json after acquisition and saves a rotated token before returning.
//! Go never composes a profile path.
//!
//! # Not faked
//!
//! The process id and the hostname are compiled out of `stack-profile` on
//! wasm32, not stubbed: the creating half of `DeviceIdentity` is
//! native-only, and this module exposes only its read. A guest that could
//! mint an identity named after a made-up hostname would be worse than one
//! that cannot.
//!
//! Split into:
//!
//! - [`ops`], [`status`], [`headers`] — everything that is pure logic over a
//!   `ProfileStore` and bytes. Compiles and unit-tests on the native host
//!   target (`cargo test` here) against a temporary directory.
//! - [`auth`], [`host`] (wasm32 only) — stack-auth strategies and host HTTP.
//! - [`abi`] (wasm32 only) — the export surface, over the conventions
//!   every guest shares (`stack_guest_abi`).

pub mod headers;
pub mod ops;
pub mod status;

#[cfg(target_arch = "wasm32")]
pub mod auth;
#[cfg(target_arch = "wasm32")]
pub mod host;

// The ABI's packed u64 results embed 32-bit pointers and its bounds checks
// read the wasm linear-memory size, so this module only exists on wasm32.
// A native build therefore exports no sa_* symbols at all — failing loudly
// at symbol lookup — instead of a silently wrong ABI.
#[cfg(target_arch = "wasm32")]
pub mod abi;
