//! Encrypting values whose type is known only at runtime.
//!
//! Everything else in this crate is typed: a target names its source type,
//! and the operations it composes are reached through bounds — `Encrypt` for
//! a ciphertext, [`PrfValue`](vitaminc_prf::PrfValue) for an equality term,
//! `AsRef<str>` for a match term. That is what makes a term a cross-language
//! contract: `equality_term(34u32)` derives the same bytes wherever it is
//! called from, because `34u32` is the same value everywhere.
//!
//! An FFI binding cannot reach those bounds. Its field types arrive as wire
//! data, so there is no Rust type to name — and no dynamic value can satisfy
//! `AsRef<str>`, which is total. Something has to look at the value and pick
//! the typed operation. This module is that something, written once here
//! rather than once per language binding.
//!
//! The runtime value is [`FfiValue`], vitaminc's language-neutral value tree
//! and the type every binding already funnels through.
//!
//! # What is here
//!
//! * [`context`](context()) — an [`FfiValue`] read as an encryption context.
//! * [`term`](term()) — one index term for a value, dispatched on its variant.
//! * [`record`] — the runtime form of `#[derive(EncryptFrom)]`: a *plan*
//!   says per field what context to bind and what outputs to produce, and
//!   the whole call seals from one batched key request.
//! * [`Scope`] — which cipher an opening operation decrypts through.
//!
//! # What is not here
//!
//! Encrypting a whole value is not: [`FfiValue`] implements `Encrypt`
//! already, so `keyset.encrypt(value, aad)` is the whole of it and needs
//! nothing from this module.
//!
//! # Stability
//!
//! The output keys this module spells (`"c"`, `"eq"`, `"match"`, `"ore"`,
//! `"ope"`) are **wire format**, not just API: they are map keys in stored
//! ciphertext, so a row written under one spelling is read under the same
//! spelling or not at all. They are fixed here so that bindings in different
//! languages agree on them by construction rather than by each re-deriving
//! them. Their long-term home is beside vitaminc's frozen tag table, which
//! already owns this class of constant.
//!
//! For the same reason the enums that spell them — [`Output`] and
//! [`TermKind`] — are *not* `#[non_exhaustive]`, against this workspace's
//! usual rule for public enums: a new output is a wire-format addition every
//! binding has to be taught, and an exhaustive match is how the compiler
//! tells a binding author that. [`Scope`] is exhaustive for a different
//! reason, given on the type.
mod context;
pub mod record;
mod term;

use std::fmt;

pub use context::{borrowed, context};
pub use record::{FieldPlan, Output, Plan};
pub use term::{term, Scalar, TermKind};
/// vitaminc's language-neutral value tree — the runtime value every binding
/// funnels through. Its transport codec is `vitaminc_aead_value::transport`,
/// which stays the binding's: this crate takes and returns values, never
/// encoded bytes.
pub use vitaminc_aead_value::FfiValue;

use crate::{KeysetCipher, StackCipher};

/// Which cipher an opening operation decrypts through: the client, or one
/// of its keysets.
///
/// This is the runtime form of the crate's *scope* (what a `Pending` is
/// built through, and so what it may open — [`CipherScope`](crate::CipherScope)
/// is the trait both ciphers implement). [`StackCipher`] and
/// [`KeysetCipher`] both open, and neither is the other's supertype: the
/// client opens a leaf sealed under any of its keysets, while a keyset
/// cipher opens only its own and fails a foreign leaf with
/// [`Error::ForeignKeyset`](crate::Error::ForeignKeyset). That refusal is
/// the keyset cipher's, made when the pending is built and before any key
/// is retrieved; this enum only names which of the two a call goes through,
/// because a binding's caller makes that choice at runtime and a typed
/// caller makes it by naming the cipher.
///
/// Not `#[non_exhaustive]`: the two variants are the two ciphers this crate
/// has, and a binding dispatches on them (the Go guest does, per selector).
/// A third would be a new cipher type, which is a larger change than adding
/// a variant here.
pub enum Scope<'c, K> {
    /// Leaves from any keyset the client holds: one batched retrieval per
    /// keyset the leaves were sealed under.
    Client(&'c StackCipher<K>),
    /// Leaves from this keyset only.
    Keyset(KeysetCipher<'c, K>),
}

// By hand rather than derived, so `K: Debug` is not demanded: neither cipher
// demands it of its own `Debug`, and a data-key source rarely offers one.
impl<K> fmt::Debug for Scope<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Client(cipher) => f.debug_tuple("Client").field(cipher).finish(),
            Scope::Keyset(keyset) => f.debug_tuple("Keyset").field(keyset).finish(),
        }
    }
}

/// The UTF-8 inside a string leaf. Valid by `Utf8String`'s construction
/// invariant; checked rather than assumed because this is boundary code.
fn utf8(s: &vitaminc_aead_value::Utf8String) -> Option<&str> {
    std::str::from_utf8(s.risky_ref()).ok()
}

/// What went wrong in a dynamic operation.
///
/// The split that matters to a caller is malformed input versus something
/// else: every variant but [`Cipher`](Error::Cipher) and
/// [`Internal`](Error::Internal) is a statement about the value or the
/// request, decided before any key is minted or retrieved. `Cipher` is the
/// operation failing; `Internal` is this module's own bug. A binding maps
/// them to its own status codes on those lines, and must not report
/// `Internal` as the caller's fault.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A value used as an encryption context is not one — a boolean, float,
    /// null, object or passthrough, or a string that is not UTF-8 — or it is
    /// a context that renders empty. Leaves take a
    /// [`NonEmpty`](vitaminc_protected::NonEmpty) and nothing else, so an
    /// empty context is refused where it is read rather than sealed under.
    #[error("value cannot be read as a non-empty encryption context")]
    Context,

    /// A term was asked for a value the scheme defines no such term for: a
    /// container, null or passthrough (which have no term semantics at all),
    /// or a scalar outside the kind's domain — equality over a float or a
    /// boolean, match over anything but text. See
    /// [`TermKind::supports`].
    #[error("no {kind} term is defined for this value")]
    Term {
        /// The kind that was asked for.
        kind: TermKind,
    },

    /// A record plan is malformed: not an object of field specs, empty,
    /// missing or duplicating an output, or carrying a key that is not
    /// `"context"` or `"outputs"`.
    #[error("record plan is malformed")]
    Plan,

    /// A record source does not fit its plan: not an object (or an array of
    /// them), a field the plan does not name, a plan field the source does
    /// not carry or carries twice, or a passthrough or a repeated map key
    /// under a field the plan seals.
    #[error("record source does not fit the plan")]
    Source,

    /// A stored record does not fit its plan: not a map (or a sequence of
    /// them), a ciphertext-bearing field that is absent or given twice, or
    /// has no `"c"` node or two of them, a repeated map key under `"c"`, or
    /// a passthrough under `"c"` — which would hand back unauthenticated
    /// bytes as if they had been opened.
    #[error("stored record does not fit the plan")]
    Record,

    /// An invariant this module maintains did not hold — a slot count that
    /// did not line up, a re-proof that should not have been able to fail.
    /// Always a bug here, never a statement about the caller's data.
    #[error("internal invariant violated")]
    Internal,

    /// Sealing, opening or deriving failed.
    #[error(transparent)]
    Cipher(#[from] crate::Error),
}
