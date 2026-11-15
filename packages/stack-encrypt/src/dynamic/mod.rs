//! Encrypting values whose type is known only at runtime.
//!
//! Everything else in this crate is typed: a target names its source type,
//! and the operations it composes are reached through bounds — `Encrypt` for
//! a ciphertext or an equality term, `AsRef<str>` for a match term. That is what makes a term a cross-language
//! contract: `equality_term(34u32)` derives the same bytes wherever it is
//! called from, because `34u32` is the same value everywhere.
//!
//! An FFI binding cannot reach those bounds. Its field types arrive as wire
//! data, so there is no Rust type to name — and no dynamic value can satisfy
//! `AsRef<str>`, which is total. Something has to look at the value and pick
//! the typed operation. This module is that something, written once here
//! rather than once per language binding.
//!
//! A term is derived from anything that describes itself to vitaminc
//! ([`Encrypt`](crate::Encrypt)), walked to its one scalar: a guest
//! walks the transport frame it was handed in place, with no tree built.
//! A plaintext the engine holds is a [`ValueFrame`]: one value as its
//! transport frame, in a buffer wiped when it drops. A record's source is
//! walked once and split into one frame per field; a field is sealed and
//! indexed by walking its frame into the encrypting sink and the term
//! derivers; and a record opens straight into a frame (a value describes
//! itself once, and sinks consume it). A binding's control
//! data (a plan, a context, query statistics) is read from its frame by
//! serde (`vitaminc_aead_frame::serde`) into a typed message, with no tree
//! built.
//!
//! # What is here
//!
//! * [`context`](context()) — a frame read as an encryption context.
//! * [`ValueFrame`] — the engine's plaintext for a value whose type is known
//!   only at run time, and the value model it holds.
//! * [`term`](term()) — one index term for a value, derived at the one
//!   scalar it is walked to.
//! * [`record`] — a record's declaration as data, *lowered* into the
//!   combinators in [`target`](crate::target) and run by the engine: the
//!   same combinators the derive composes, so a record written from any
//!   language is the same bytes. The one step that stays dynamic is
//!   dispatching a value whose type is known only at run time to the typed
//!   term operation, which [`IndexSpec`]'s `Index` impls do.
//! * [`read_json`] and [`json_frame`] — a `json` field's document, from
//!   the JSON text a binding hands over and back to it.
//! * [`TargetResolver`] — the EQL types a build holds, installed by the host
//!   that links them, so a plan field may name one as its target and the
//!   lowering runs that type's own plan in the same request; [`NoTargets`]
//!   is the build without them.
//! * [`TermBytes`] — the term a field lowered from data derives, as its
//!   frozen bytes. Such a field's plaintext is a [`ValueFrame`].
//! * [`query_term`], [`verify`] and [`target_limit`] — a query named by
//!   operator ([`Op`]) on a plan field, and a probabilistic term's two
//!   questions, over a page of decrypted values and over [`Stats`](crate::op::Stats),
//!   and [`field_operators`], the operators a plan field answers, for a
//!   generator to ask before the program runs.
//! * [`CipherRef`](crate::CipherRef) — the cipher that a decrypt
//!   operation runs through. Pass `&cipher`, or pass `&keyset` to limit
//!   the operation to one keyset.
//!
//! # What is not here
//!
//! Encrypting a whole value is not: a [`ValueFrame`], like any source,
//! implements `Encrypt` already, so `keyset.encrypt_tree(value, aad)` is the whole
//! of it and needs nothing from this module. Nor is a second executor: nothing here calls
//! the term functions or the seal path to produce a record. A capability a
//! data plan needs and the combinators lack is added to the combinators,
//! once.
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
//! the type it was sealed as. A declared type is a [`ValueKind`], whose
//! names are frozen. What a kind means to an index ([`admits`]) and to a
//! query value ([`read`]) is stated over it; the bytes are vitaminc's, from
//! the tagged leaf a value of the kind seals as ([`record`]). Every field with a term output declares one;
//! a plan whose indexed field has none is refused when it is built
//! ([`Error::UntypedIndex`], naming the field).
//!
//! For the same reason the enums that spell them — [`Output`],
//! [`IndexSpec`] and [`ValueKind`] — are *not* `#[non_exhaustive]`, against this workspace's
//! usual rule for public enums: a new output is a wire-format addition every
//! binding has to be taught, and an exhaustive match is how the compiler
//! tells a binding author that.
mod context;
mod json;
mod json_query;
mod kind;
pub mod planned;
mod query;
pub mod record;
mod target;
mod term;
#[cfg(test)]
mod test_frame;
mod value_frame;

/// The document a `json` field's value holds, as [`read_json`] returns it:
/// [`crate::json::JsonPlaintext`], named here for a binding that reaches
/// the engine through this module.
pub use crate::json::JsonPlaintext;
pub use context::{borrowed, context};
pub use json::{json_frame, read_json, JsonValueError};
/// The value kinds, the type a plan field declares in its `"type"` key. A
/// kind's names are frozen wire format; see [`admits`] and [`read`] for what
/// a kind means to this engine.
pub use kind::{admits, not_admitted, read, ParseValueKindError, ValueKind};
pub use planned::{DynamicQuery, FieldHandle, Planned, QueryPlan};
#[allow(deprecated)]
pub use query::OpSpec;
pub use query::{
    check_json_open, check_query, field_operators, json_open, query_term, target_limit, verify,
    Fidelity, Op, Operand, OperatorEntry, QueryTerm,
};
pub use record::{FieldPlan, NullMode, Output, Plan};
pub use target::{NoTargets, TargetDescriptor, TargetError, TargetOptions, TargetResolver};
pub use term::{term, TermBytes};
pub use value_frame::{Children, FromFrameError, Modeled, Opening, ValueFrame};

/// vitaminc's value model, the sinks and scalar types a value describes
/// itself through. A binding implements [`Encrypt`](crate::Encrypt) for its
/// own values with it, as [`read`] takes them. Re-exported so a binding
/// builds against the vitaminc this crate does. Two versions of vitaminc in
/// one build do not fail loudly: a [`ValueFrame`] stops meeting the other
/// version's `Decrypt` bound.
pub use vitaminc_aead::plaintext;
/// vitaminc's transport frame and ciphertext codec (`vitaminc-aead-frame`,
/// with its `serde` module): the bytes a binding hands this module, and the
/// codec its ciphertexts cross in. Re-exported for the same reason as
/// [`plaintext`].
pub use vitaminc_aead_frame as frame;

/// Bytes, written as a frame's bytes leaf rather than a list of integers.
struct WireBytes<'a>(&'a [u8]);

impl serde::Serialize for WireBytes<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

pub use crate::refusal::{Error, Reason};
