//! Structured contexts for the record and term paths.
//!
//! A plan field's context, and a term probe's, arrives as an [`FfiValue`]
//! and becomes a [`ContextPart`] tree: the guest's runtime form of the
//! context a Rust caller builds statically. A Rust
//! `#[derive(EncryptFrom)]` row sealed with `encrypt_into_with_context(row,
//! 7u64)` binds each field under `("users/age", 7u64)` — a `NonEmpty<(&str,
//! u64)>` — and a plan spells the same context as `["users/age", 7u64]`.
//! The two must agree byte for byte on *both* derivations a context feeds:
//!
//! * **AAD** (the ciphertext binding, and the ZeroKMS descriptor rendered
//!   from its parts): a [`ContextPart`] is an [`AadPiece`], so a list
//!   encodes as the PAE of its parts exactly as a tuple does, and
//!   [`Descriptor`](stack_encrypt::Descriptor) renders it the same way.
//! * **PRF context** (the index terms' domain separation): a leaf hands
//!   itself to the standard type's own [`IntoPrfContext`] impl — text is
//!   `String`'s, an integer is that integer's — so it carries the same
//!   typed encoding, and a list is [`PrfContext::pae`] of its parts, which
//!   is what vitaminc's tuple impl produces.
//!
//! Neither encoding is re-derived here: the leaves *are* the standard
//! impls, and the list framing is the one public `pae` both crates expose.
//! The unit tests below pin the agreement against `nonempty!(..).with(..)`
//! on both sides, and `tests/native_ops.rs` pins it end to end: a plan's
//! stored terms equal native probes under the tuple, and its `"c"` leaf
//! opens natively under the tuple.
//!
//! # Shape
//!
//! ```text
//! context := <string> | <bytes> | <i32> | <i64> | <u32> | <u64> | [ context, ... ]
//! ```
//!
//! This module is the one home of that grammar; the plan parser, the ABI
//! docs and the Go bindings plan point here.
//!
//! A bare string is the flat form every plan used before this module: one
//! text part, the field's whole context, same bytes as before. An array is
//! a list; it may nest. Text and bytes with the same content are distinct
//! on the PRF side (UTF-8 versus bytes encodings) though they share AAD
//! bytes — the same distinction the Rust types make.  Booleans, floats,
//! null, undefined, objects and passthroughs are not contexts and are
//! refused as [`STATUS_ENCODING`].
//!
//! # Which Rust contexts a list spells
//!
//! * `["users/age", 7u64]` is `nonempty!("users/age").with(7u64)`: a
//!   two-element list is the pair.
//! * `NonEmpty::with` nests to the **left**: `nonempty!("a").with(7u64)
//!   .with("eu")` is `(("a", 7u64), "eu")`, spelled `[["a", 7u64], "eu"]`.
//!   A flat three-element list is a different context (a three-part PAE)
//!   that no `.with()` chain produces; `a_left_nested_list_is_the_with_chain`
//!   pins both facts.
//! * A one-element list is *not* the bare part: it is PAE-framed, as
//!   `Some(x)` is on the AAD side. On the PRF side vitaminc currently tags
//!   `Some(x)` with an `option-some` domain, so `[x]` matches a Rust
//!   `Some(x)` for the ciphertext and the descriptor but **not** for index
//!   terms. That is a divergence inside vitaminc between a context's two
//!   derivations, and vitaminc#335 removes it (`Some(x)` becomes the
//!   one-element list on both sides, and this type becomes `AadPiece`
//!   itself). Until it ships, a Rust row that Go must query must not be
//!   sealed under an `Option` context; `a_one_element_list_is_not_the_bare_part`
//!   and `a_one_element_list_is_not_yet_some_on_the_prf_side` pin the
//!   current state so the fix shows up as a test change.
//!
//! # Emptiness
//!
//! [`parse_context`] returns a [`NonEmpty`], proven once at the boundary:
//! an empty string or byte string is empty, an integer never is, and a list
//! is empty when every part is (so `[]` and `[""]` are, `["", 7]` is not) —
//! the rule vitaminc's `Option` and tuple impls follow.

use std::borrow::Cow;

use stack_encrypt::{Aad, AadPiece, IntoAad, IntoPrfContext, MaybeEmpty, NonEmpty, PrfContext};
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::Controlled;

use crate::status::STATUS_ENCODING;

/// One part of a context, or a list of parts. See the [module docs](self)
/// for the encoding each variant carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextPart {
    /// Text: [`AadPiece::Text`]; PRF-encoded as a `String`.
    Text(String),
    /// Opaque bytes: [`AadPiece::Bytes`]; PRF-encoded as a `Vec<u8>`.
    Bytes(Vec<u8>),
    /// [`AadPiece::I32`]; PRF-encoded as an `i32`.
    I32(i32),
    /// [`AadPiece::I64`]; PRF-encoded as an `i64`.
    I64(i64),
    /// [`AadPiece::U32`]; PRF-encoded as a `u32`.
    U32(u32),
    /// [`AadPiece::U64`]; PRF-encoded as a `u64`.
    U64(u64),
    /// [`AadPiece::List`]; PRF-encoded as the PAE of its parts.
    List(Vec<ContextPart>),
}

impl<'a> IntoAad<'a> for ContextPart {
    fn into_aad(self) -> Aad<'a> {
        self.into_aad_piece().into_aad()
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        match self {
            ContextPart::Text(text) => AadPiece::Text(Cow::Owned(text)),
            ContextPart::Bytes(bytes) => AadPiece::Bytes(Cow::Owned(bytes)),
            ContextPart::I32(v) => AadPiece::I32(v),
            ContextPart::I64(v) => AadPiece::I64(v),
            ContextPart::U32(v) => AadPiece::U32(v),
            ContextPart::U64(v) => AadPiece::U64(v),
            ContextPart::List(parts) => {
                AadPiece::List(parts.into_iter().map(IntoAad::into_aad_piece).collect())
            }
        }
    }
}

impl<'a> IntoPrfContext<'a> for ContextPart {
    fn into_prf_context(self) -> PrfContext<'a> {
        match self {
            ContextPart::Text(text) => text.into_prf_context(),
            ContextPart::Bytes(bytes) => bytes.into_prf_context(),
            ContextPart::I32(v) => v.into_prf_context(),
            ContextPart::I64(v) => v.into_prf_context(),
            ContextPart::U32(v) => v.into_prf_context(),
            ContextPart::U64(v) => v.into_prf_context(),
            ContextPart::List(parts) => {
                pae_of(parts.into_iter().map(IntoPrfContext::into_prf_context))
            }
        }
    }
}

/// Borrowed forms, so a plan's context is bound once at parse and then
/// handed to every output of every row without cloning the tree: the
/// leaves borrow (`Cow::Borrowed`, `&str`, `&[u8]`), and the consumers
/// (`encrypt_with_aad`, `into_pending`, `decrypt_into`, the term
/// derivations) take the context by value with a free lifetime and own
/// what they keep before any await.
impl<'a> IntoAad<'a> for &'a ContextPart {
    fn into_aad(self) -> Aad<'a> {
        self.into_aad_piece().into_aad()
    }

    fn into_aad_piece(self) -> AadPiece<'a> {
        match self {
            ContextPart::Text(text) => AadPiece::Text(Cow::Borrowed(text)),
            ContextPart::Bytes(bytes) => AadPiece::Bytes(Cow::Borrowed(bytes)),
            ContextPart::I32(v) => AadPiece::I32(*v),
            ContextPart::I64(v) => AadPiece::I64(*v),
            ContextPart::U32(v) => AadPiece::U32(*v),
            ContextPart::U64(v) => AadPiece::U64(*v),
            ContextPart::List(parts) => {
                AadPiece::List(parts.iter().map(IntoAad::into_aad_piece).collect())
            }
        }
    }
}

impl<'a> IntoPrfContext<'a> for &'a ContextPart {
    fn into_prf_context(self) -> PrfContext<'a> {
        match self {
            ContextPart::Text(text) => text.as_str().into_prf_context(),
            ContextPart::Bytes(bytes) => bytes.as_slice().into_prf_context(),
            ContextPart::I32(v) => v.into_prf_context(),
            ContextPart::I64(v) => v.into_prf_context(),
            ContextPart::U32(v) => v.into_prf_context(),
            ContextPart::U64(v) => v.into_prf_context(),
            ContextPart::List(parts) => pae_of(parts.iter().map(IntoPrfContext::into_prf_context)),
        }
    }
}

/// The PAE of already-derived parts: what vitaminc's `(A, B)` impl does
/// for two, for any number.
fn pae_of<'a>(parts: impl Iterator<Item = PrfContext<'a>>) -> PrfContext<'static> {
    let encoded: Vec<PrfContext<'a>> = parts.collect();
    let pieces: Vec<&[u8]> = encoded.iter().map(PrfContext::as_bytes).collect();
    PrfContext::pae(&pieces)
}

impl MaybeEmpty for ContextPart {
    fn is_empty(&self) -> bool {
        match self {
            ContextPart::Text(text) => text.is_empty(),
            ContextPart::Bytes(bytes) => bytes.is_empty(),
            ContextPart::I32(_)
            | ContextPart::I64(_)
            | ContextPart::U32(_)
            | ContextPart::U64(_) => false,
            ContextPart::List(parts) => parts.iter().all(MaybeEmpty::is_empty),
        }
    }
}

/// Parse a context from its decoded [`FfiValue`] form and prove it
/// non-empty. Anything outside the shape in the [module docs](self), and
/// an empty context, is [`STATUS_ENCODING`].
pub fn parse_context(value: FfiValue) -> Result<NonEmpty<ContextPart>, u32> {
    NonEmpty::new(part_of(value)?).map_err(|_| STATUS_ENCODING)
}

fn part_of(value: FfiValue) -> Result<ContextPart, u32> {
    Ok(match value {
        // Valid UTF-8 by `Utf8String`'s construction invariant; checked
        // rather than assumed because this is boundary code. The payload
        // moves out of its `Protected` rather than being copied: a context
        // is not secret, and the copy would only be wiped and freed.
        FfiValue::String(s) => ContextPart::Text(
            String::from_utf8(s.into_inner().risky_unwrap()).map_err(|_| STATUS_ENCODING)?,
        ),
        FfiValue::Bytes(bytes) => ContextPart::Bytes(bytes.risky_unwrap()),
        FfiValue::Int32(v) => ContextPart::I32(v),
        FfiValue::Int64(v) => ContextPart::I64(v),
        FfiValue::UInt32(v) => ContextPart::U32(v),
        FfiValue::UInt64(v) => ContextPart::U64(v),
        // Nesting depth is bounded by the codec's `MAX_DEPTH` before the
        // value reaches here.
        FfiValue::Array(items) => ContextPart::List(
            items
                .into_iter()
                .map(part_of)
                .collect::<Result<Vec<_>, u32>>()?,
        ),
        FfiValue::Null
        | FfiValue::Undefined
        | FfiValue::Bool(_)
        | FfiValue::Float32(_)
        | FfiValue::Float64(_)
        | FfiValue::Object(_)
        | FfiValue::Passthrough(_) => return Err(STATUS_ENCODING),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_encrypt::nonempty;
    use vitaminc_protected::Protected;

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    #[test]
    fn a_bare_string_is_the_flat_context() {
        let parsed = parse_context(s("users/age")).expect("flat context");
        assert_eq!(parsed.get(), &ContextPart::Text("users/age".to_string()));
        assert_eq!(
            parsed.into_inner().into_aad().as_bytes(),
            "users/age".into_aad().as_bytes()
        );
    }

    #[test]
    fn a_list_encodes_as_the_tuple_on_both_sides() {
        let parsed = parse_context(FfiValue::Array(vec![s("users/age"), FfiValue::UInt64(7)]))
            .expect("extended context");
        let tuple = nonempty!("users/age").with(7u64);
        assert_eq!(
            parsed.clone().into_inner().into_aad().as_bytes(),
            tuple.into_aad().as_bytes()
        );
        assert_eq!(
            parsed.into_inner().into_prf_context().as_bytes(),
            tuple.into_prf_context().as_bytes()
        );
    }

    #[test]
    fn a_list_renders_the_descriptor_the_tuple_does() {
        use stack_encrypt::Descriptor;
        let parsed = parse_context(FfiValue::Array(vec![s("users/age"), FfiValue::UInt64(7)]))
            .expect("extended context");
        assert_eq!(
            Descriptor::of(parsed.into_inner()).as_str(),
            "users/age|7u64"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users/age").with(7u64)).as_str(),
            "users/age|7u64"
        );
    }

    #[test]
    fn a_nested_list_encodes_as_the_nested_tuple() {
        let parsed = parse_context(FfiValue::Array(vec![
            s("users/age"),
            FfiValue::Array(vec![s("t"), FfiValue::Int32(-3)]),
        ]))
        .expect("nested context");
        let tuple = ("users/age", ("t", -3i32));
        assert_eq!(
            parsed.clone().into_inner().into_aad().as_bytes(),
            tuple.into_aad().as_bytes()
        );
        assert_eq!(
            parsed.into_inner().into_prf_context().as_bytes(),
            tuple.into_prf_context().as_bytes()
        );
    }

    /// The borrowed impls are the owned ones without the clone.
    #[test]
    fn borrowed_and_owned_forms_encode_alike() {
        let parsed = parse_context(FfiValue::Array(vec![
            s("users/age"),
            FfiValue::Array(vec![
                FfiValue::Bytes(Protected::new(b"k".to_vec())),
                FfiValue::Int64(-1),
            ]),
        ]))
        .expect("context");
        let owned = parsed.clone().into_inner();
        let borrowed = NonEmpty::new(parsed.get()).expect("a non-empty context borrows non-empty");
        assert_eq!(
            borrowed.into_aad().as_bytes(),
            owned.clone().into_aad().as_bytes(),
            "AAD bytes differ between the borrowed and owned forms"
        );
        assert_eq!(
            NonEmpty::new(parsed.get())
                .expect("non-empty")
                .into_prf_context()
                .as_bytes(),
            owned.into_prf_context().as_bytes(),
            "PRF bytes differ between the borrowed and owned forms"
        );
    }

    /// `NonEmpty::with` nests to the left, so a `.with().with()` chain is
    /// the left-nested list; a flat list of three is a different context.
    #[test]
    fn a_left_nested_list_is_the_with_chain() {
        let chain = nonempty!("a").with(7u64).with("eu");
        let nested = parse_context(FfiValue::Array(vec![
            FfiValue::Array(vec![s("a"), FfiValue::UInt64(7)]),
            s("eu"),
        ]))
        .expect("nested")
        .into_inner();
        let flat = parse_context(FfiValue::Array(vec![s("a"), FfiValue::UInt64(7), s("eu")]))
            .expect("flat")
            .into_inner();
        assert_eq!(
            nested.clone().into_aad().as_bytes(),
            chain.into_aad().as_bytes(),
            "the left-nested list is not the with-chain on the AAD side"
        );
        assert_eq!(
            nested.clone().into_prf_context().as_bytes(),
            chain.into_prf_context().as_bytes(),
            "the left-nested list is not the with-chain on the PRF side"
        );
        assert_ne!(
            flat.clone().into_aad().as_bytes(),
            nested.clone().into_aad().as_bytes(),
            "a flat three-part list must not collide with the nested pair"
        );
        assert_ne!(
            flat.into_prf_context().as_bytes(),
            nested.into_prf_context().as_bytes(),
            "a flat three-part list must not collide with the nested pair"
        );
    }

    /// The state vitaminc#335 changes: `[x]` is `Some(x)` for the AAD and
    /// the descriptor, and not yet for index terms. When the PRF `Option`
    /// impl follows the parts view, the `assert_ne!` here flips to
    /// `assert_eq!` and the module docs lose their caveat.
    #[test]
    fn a_one_element_list_is_not_yet_some_on_the_prf_side() {
        use stack_encrypt::Descriptor;
        let list = parse_context(FfiValue::Array(vec![FfiValue::UInt64(7)]))
            .expect("list")
            .into_inner();
        let some = Some(7u64);
        assert_eq!(
            list.clone().into_aad().as_bytes(),
            some.into_aad().as_bytes(),
            "[x] and Some(x) share AAD bytes"
        );
        assert_eq!(
            Descriptor::of(list.clone()).as_str(),
            Descriptor::of(some).as_str(),
            "[x] and Some(x) render the same descriptor"
        );
        assert_ne!(
            list.into_prf_context().as_bytes(),
            some.into_prf_context().as_bytes(),
            "vitaminc#335 has landed: [x] now equals Some(x) on the PRF side too — flip this to assert_eq! and drop the module-doc caveat"
        );
    }

    #[test]
    fn a_one_element_list_is_not_the_bare_part() {
        let list = parse_context(FfiValue::Array(vec![s("a")])).expect("list");
        let bare = parse_context(s("a")).expect("bare");
        assert_ne!(
            list.clone().into_inner().into_aad().as_bytes(),
            bare.clone().into_inner().into_aad().as_bytes()
        );
        assert_ne!(
            list.into_inner().into_prf_context().as_bytes(),
            bare.into_inner().into_prf_context().as_bytes()
        );
    }

    #[test]
    fn text_and_bytes_share_aad_bytes_but_not_prf_encoding() {
        let text = parse_context(s("ab")).expect("text").into_inner();
        let bytes = parse_context(FfiValue::Bytes(Protected::new(b"ab".to_vec())))
            .expect("bytes")
            .into_inner();
        assert_eq!(
            text.clone().into_aad().as_bytes(),
            bytes.clone().into_aad().as_bytes()
        );
        assert_ne!(
            text.into_prf_context().as_bytes(),
            bytes.into_prf_context().as_bytes()
        );
    }

    #[test]
    fn emptiness_follows_the_tuple_rule() {
        for (label, empty) in [
            ("an empty string", s("")),
            ("empty bytes", FfiValue::Bytes(Protected::new(Vec::new()))),
            ("an empty list", FfiValue::Array(vec![])),
            ("a list of one empty string", FfiValue::Array(vec![s("")])),
            (
                "a list of empties",
                FfiValue::Array(vec![FfiValue::Array(vec![]), s("")]),
            ),
        ] {
            assert_eq!(
                parse_context(empty).err(),
                Some(STATUS_ENCODING),
                "{label} is empty by the tuple rule and must be refused"
            );
        }
        for (label, non_empty) in [
            ("a zero integer", FfiValue::UInt64(0)),
            (
                "an empty string beside an integer",
                FfiValue::Array(vec![s(""), FfiValue::Int32(0)]),
            ),
            (
                "a nested non-empty list",
                FfiValue::Array(vec![FfiValue::Array(vec![s("x")])]),
            ),
        ] {
            assert!(
                parse_context(non_empty).is_ok(),
                "{label} carries bytes and must be accepted"
            );
        }
    }

    #[test]
    fn non_context_values_are_encoding_errors() {
        for (label, bad) in [
            ("null", FfiValue::Null),
            ("undefined", FfiValue::Undefined),
            ("a boolean", FfiValue::Bool(true)),
            ("a float32", FfiValue::Float32(1.0)),
            ("a float64", FfiValue::Float64(1.0)),
            (
                "an object",
                FfiValue::Object(vec![("k".to_string(), s("v"))]),
            ),
            (
                "a list with a boolean in it",
                FfiValue::Array(vec![s("ok"), FfiValue::Bool(false)]),
            ),
        ] {
            assert_eq!(
                parse_context(bad).err(),
                Some(STATUS_ENCODING),
                "{label} is not a context and must be refused"
            );
        }
    }
}
