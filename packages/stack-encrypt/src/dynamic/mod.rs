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
//! * [`record`] — a fields plan spelled as data, *lowered* into the plan
//!   builder ([`Plan`](crate::Plan)) and run by the engine: the same code a
//!   Rust chain and the derive run, so a record written from any language
//!   is the same bytes (ADR-0007). The one step that stays dynamic is
//!   dispatching a value whose type is known only at run time to the typed
//!   term operation, which [`IndexSpec`]'s `Index` impls do.
//! * [`TargetResolver`] — the EQL types a build holds, installed by the host
//!   that links them, so a plan field may name one as its target and the
//!   lowering runs that type's own plan in the same request; [`NoTargets`]
//!   is the build without them.
//! * [`Value`] — an [`FfiValue`] as a plan field's plaintext, the type of
//!   every field lowered from data; [`TermBytes`] — the term such a field
//!   derives, as its frozen bytes.
//! * [`Scope`] — which cipher an opening operation decrypts through.
//!
//! # What is not here
//!
//! Encrypting a whole value is not: [`FfiValue`] implements `Encrypt`
//! already, so `keyset.encrypt(value, aad)` is the whole of it and needs
//! nothing from this module. Nor is a second executor: nothing here calls
//! the term functions or the seal path to produce a record. A capability a
//! data plan needs and the builder lacks is added to the builder, once.
//!
//! # Stability
//!
//! The output keys this module spells (`"c"`, `"eq"`, `"match"`, `"ore"`,
//! `"ope"`, `"passthrough"`) are **wire format**, not just API: they are map
//! keys in stored ciphertext, so a row written under one spelling is read
//! under the same spelling or not at all. They are fixed here so that
//! bindings in different languages agree on them by construction rather
//! than by each re-deriving them. Their long-term home is beside vitaminc's
//! frozen tag table, which already owns this class of constant.
//!
//! A plan field's `"type"` names (`"int64"`, `"string"`, …) are wire format
//! in the same way: a binding spells them, and a stored row opens only under
//! the type it was sealed as. They are not this crate's: a declared type is
//! vitaminc's [`ValueKind`], re-exported here, whose names vitaminc freezes
//! beside its tag table. This crate adds only what a kind means to an index
//! ([`admits`]) and to a query value ([`read`]); it decides nothing about
//! the bytes ([`record`]). A field without `"type"` is dispatched on each
//! value's own tag; that is transitional, and [`record::plan`] says until
//! when.
//!
//! For the same reason the enums that spell them — [`Output`],
//! [`IndexSpec`] and [`ValueKind`] — are *not* `#[non_exhaustive]`, against this workspace's
//! usual rule for public enums: a new output is a wire-format addition every
//! binding has to be taught, and an exhaustive match is how the compiler
//! tells a binding author that. [`Scope`] is exhaustive for a different
//! reason, given on the type.
mod context;
mod kind;
pub mod record;
mod target;
mod term;
mod value;

use std::fmt;

pub use context::{borrowed, context};
pub use kind::{admits, read};
pub use record::{FieldPlan, Output, Plan};
pub use target::{NoTargets, TargetDescriptor, TargetError, TargetResolver};
pub use term::{term, Scalar, TermBytes};
pub use value::Value;
/// vitaminc's language-neutral value tree — the runtime value every binding
/// funnels through. Its transport codec is `vitaminc_aead_value::transport`,
/// which stays the binding's: this crate takes and returns values, never
/// encoded bytes.
pub use vitaminc_aead_value::FfiValue;
/// vitaminc's value kinds: the type a plan field declares in its `"type"`
/// key. Its names are frozen wire format; see [`admits`] and [`read`] for
/// what a kind means to this engine.
pub use vitaminc_aead_value::ValueKind;

use crate::target::IndexSpec;
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
/// `Internal` as the caller's fault. The record path's operations hand back
/// the engine's [`Pending`](crate::Pending), whose failure is the crate's
/// [`Error`](crate::Error); a [`Plan`](crate::Error::Plan) failure there is
/// again a statement about the caller's data.
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
    /// [`IndexSpec::supports`].
    #[error("no {kind} term is defined for this value")]
    Term {
        /// The index that was asked for.
        kind: IndexSpec,
    },

    /// A record plan is malformed: not an object of field specs, empty,
    /// missing or duplicating an output, carrying a key that is not
    /// `"context"`, `"outputs"` or `"type"`, naming a type that is not one,
    /// asking for an index its declared type is not defined for, giving a
    /// field a context that is not a label a fields plan can seal it under,
    /// or declaring what the plan builder refuses (two fields under one
    /// identity, fields under different contexts).
    #[error("record plan is malformed")]
    Plan,

    /// A record source does not fit its plan: not an object (or an array of
    /// them), a field the plan does not name, a plan field the source does
    /// not carry or carries twice, or a passthrough or a repeated map key
    /// under a field the plan seals, or a value of another type than its
    /// field declares. Also a query value that cannot be read as its field's
    /// type ([`read`]).
    #[error("record source does not fit the plan")]
    Source,

    /// A stored record does not fit its plan: not a map (or a sequence of
    /// them), a ciphertext-bearing field that is absent or given twice, or
    /// has no `"c"` node or two of them, a repeated map key under `"c"`, a
    /// passthrough under `"c"` — which would hand back unauthenticated
    /// bytes as if they had been opened — or a passthrough field that is
    /// absent, carries no `"passthrough"` node, or carries a value of
    /// another type than it declares. A sealed field that opens to a value
    /// of another type than it declares fails the pending instead
    /// ([`PlanError::FieldType`](crate::PlanError::FieldType)): the type tag
    /// is inside the AEAD envelope.
    #[error("stored record does not fit the plan")]
    Record,

    /// An invariant this module maintains did not hold — a slot count that
    /// did not line up, a re-proof that should not have been able to fail.
    /// Always a bug here, never a statement about the caller's data.
    #[error("internal invariant violated")]
    Internal,

    /// A plan field names an EQL type as its target and the name, the
    /// field's label or type, or the value does not fit: the build holds no
    /// EQL types, no type has the name, the engine cannot produce it yet,
    /// the plan is extended, or the value is of another kind. Decided when
    /// the plan is built or the value is read, before any key is touched
    /// — save [`TargetError::Other`], which is the resolver's own failure.
    #[error(transparent)]
    Target(#[from] TargetError),

    /// Sealing, opening or deriving failed.
    #[error(transparent)]
    Cipher(#[from] crate::Error),
}
