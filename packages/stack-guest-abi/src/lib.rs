// Security lints — the block `stack-encrypt` and `stack-auth` carry, minus
// `deny(unsafe_code)`: the export surface (`abi`) and the host import
// (`transport`) are `extern "C"` over raw pointers by nature. Every `unsafe`
// block is confined to those two wasm32-only modules and to the buffer
// registry, and documented at the site; `unsafe_op_in_unsafe_fn` keeps each
// one explicit.
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
// `abi` and `transport` only exist on wasm32, so on a native doc build their
// intra-doc links have nothing to resolve to. The wasm32 doc build
// (`mise run wasm:guest:test`) is where links are enforced.
#![cfg_attr(not(target_arch = "wasm32"), allow(rustdoc::broken_intra_doc_links))]
//! # The guest ABI the Go binding's WASI guests share
//!
//! The Go binding reaches Rust through WASI modules run by wazero: the
//! crypto guest (`bindings/go/stackencrypt/guest`, `stack-encrypt` over a
//! host-provided transport) and, per ADR-0005, the credential guest
//! (`stack-profile` and `stack-auth`). Everything a guest needs that is
//! *not* about what it does — how the host gets bytes in and out, how a
//! result is packed, what a status number means, how an HTTP request
//! crosses to the host — lives here, once, so the memory-hygiene rules are
//! written and fixed in one place and the two guests read identically from
//! the host side.
//!
//! What is here:
//!
//! - [`buffers`] — the guest-owned buffer registry: every buffer handed to
//!   the host is recorded with its true length, released through the
//!   registry (never on the host's say-so), and zeroized on the way out.
//! - [`abi`] (wasm32 only) — the `se_alloc` / `se_dealloc` exports every
//!   guest has, the packed `u64` result encoding, and the hostile-input
//!   helpers that validate a host `(ptr, len)` pair against linear memory
//!   before any slice exists.
//! - [`status`] — the status table. **One numbering for every guest**: the
//!   codes below keep their values for good, and a guest that needs more
//!   appends after them. The Go side decodes the table once.
//! - [`transport`] (wasm32 only) — the `cipherstash_transport::transport_send`
//!   host import, wrapped so a guest performs one HTTP request as a safe
//!   call and gets both response buffers back through the registry.
//! - [`headers`] — the `name: value` line format request and response
//!   headers cross the import in.
//!
//! What is deliberately *not* here: anything that names a crate a guest is
//! built over. The ZeroKMS connection over the transport, the token import
//! the crypto guest uses for its phase-1 auth, the mapping from a library's
//! error type onto the status table, and the `user-agent` a guest sends are
//! each guest's own.
//!
//! # Conventions
//!
//! The host owns every buffer lifecycle. It writes inputs into guest memory
//! obtained from `se_alloc` and releases every buffer — its own inputs and
//! the guest's outputs — with `se_dealloc`, which zeroizes before freeing.
//! Every fallible export returns one `u64`: a non-zero high half is an
//! output pointer with the length in the low half; a zero high half carries
//! a [`status`] code in the low half. Wasm modules are single-threaded; the
//! host serializes calls into one instance, and during an export the host's
//! imports may re-enter the guest only through `se_alloc`.
//!
//! The crate builds natively too — the registry and the header format have
//! no wasm in them and are unit-tested on the host — but only the wasm32
//! build has an ABI: on any other target the export and import modules do
//! not exist, so a native library built over this crate exports no `se_*`
//! symbol at all rather than a silently wrong one (the packed result would
//! truncate a 64-bit pointer). A native backend, when it comes, adds its own
//! export and import modules beside these and swaps the registry's
//! thread-local owner for a locked one (see [`buffers`]); nothing else here
//! assumes wasm.

pub mod buffers;
pub mod headers;
pub mod status;

#[cfg(target_arch = "wasm32")]
pub mod abi;
#[cfg(target_arch = "wasm32")]
pub mod transport;
