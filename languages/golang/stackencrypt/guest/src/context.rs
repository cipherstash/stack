//! Structured contexts for the record and term paths.
//!
//! A plan field's context, and a term probe's, arrives as an [`FfiValue`]
//! and becomes an [`AadPiece`] tree: vitaminc's runtime form of a context,
//! and the *identity* of one. vitaminc's law (pinned there by quickcheck
//! over every built-in context type) is that a context's two derivations
//! each equal the same derivation of its parts view:
//!
//! ```text
//! x.into_aad()         == x.into_aad_piece().into_aad()
//! x.into_prf_context() == x.into_aad_piece().into_prf_context()
//! ```
//!
//! So a Rust `#[derive(EncryptFrom)]` row sealed with
//! `encrypt_into_with_context(row, 7u64)`, which binds each field under
//! `("users/age", 7u64)` — a `NonEmpty<(&str, u64)>` — and a plan that
//! spells the same context as `["users/age", 7u64]` agree byte for byte on
//! the AAD (the ciphertext binding and the ZeroKMS descriptor rendered from
//! its parts) *and* on the PRF context (the index terms' domain separation).
//! Nothing is re-derived in this crate: the tree is handed to vitaminc's own
//! impls. The unit tests below pin the agreement against
//! `nonempty!(..).with(..)` on both sides, and `tests/native_ops.rs` pins it
//! end to end: a plan's stored terms equal native probes under the tuple,
//! and its `"c"` leaf opens natively under the tuple.
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
//! a list; it may nest as deep as the transport codec allows
//! ([`MAX_DEPTH`](vitaminc_aead_value::transport::MAX_DEPTH) levels,
//! counted from the root of the encoded value — a plan's field context
//! starts two levels down), and a deeper value is refused as
//! [`STATUS_ENCODING`] by the codec before this module sees it. Text and
//! bytes with the same content are distinct on the PRF side (UTF-8 versus
//! bytes encodings) though they share AAD bytes — the same distinction the
//! Rust types make. Booleans, floats, null, undefined, objects and
//! passthroughs are not contexts and are refused as [`STATUS_ENCODING`].
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
//! * `[x]` is `Some(x)` and `[]` is `None`, on both derivations. A
//!   one-element list is *not* the bare part: it is PAE-framed, the bare
//!   part is not; `a_one_element_list_is_some` and
//!   `a_one_element_list_is_not_the_bare_part` pin both.
//!
//! # Emptiness
//!
//! [`parse_context`] returns a [`NonEmpty`], proven once at the boundary by
//! vitaminc's own rule for the tree: an empty string or byte string is
//! empty, an integer never is, and a list is empty when every part is (so
//! `[]` and `[""]` are, `["", 7]` is not) — the rule its `Option` and tuple
//! impls follow.

use std::borrow::Cow;

use stack_encrypt::{AadPiece, NonEmpty};
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::Controlled;

use crate::status::STATUS_ENCODING;

/// Parse a context from its decoded [`FfiValue`] form and prove it
/// non-empty. Anything outside the shape in the [module docs](self), and
/// an empty context, is [`STATUS_ENCODING`].
pub fn parse_context(value: FfiValue) -> Result<NonEmpty<AadPiece<'static>>, u32> {
    NonEmpty::new(piece_of(value)?).map_err(|_| STATUS_ENCODING)
}

fn piece_of(value: FfiValue) -> Result<AadPiece<'static>, u32> {
    Ok(match value {
        // Valid UTF-8 by `Utf8String`'s construction invariant; checked
        // rather than assumed because this is boundary code. The payload
        // moves out of its `Protected` rather than being copied: a context
        // is not secret, and the copy would only be wiped and freed.
        FfiValue::String(s) => AadPiece::Text(Cow::Owned(
            String::from_utf8(s.into_inner().risky_unwrap()).map_err(|_| STATUS_ENCODING)?,
        )),
        FfiValue::Bytes(bytes) => AadPiece::Bytes(Cow::Owned(bytes.risky_unwrap())),
        FfiValue::Int32(v) => AadPiece::I32(v),
        FfiValue::Int64(v) => AadPiece::I64(v),
        FfiValue::UInt32(v) => AadPiece::U32(v),
        FfiValue::UInt64(v) => AadPiece::U64(v),
        // Nesting depth is bounded by the codec's `MAX_DEPTH` before the
        // value reaches here.
        FfiValue::Array(items) => AadPiece::List(
            items
                .into_iter()
                .map(piece_of)
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

/// A view of a context tree that borrows its text and bytes, so a plan's
/// context — parsed and proven once — can be handed to every output of
/// every row without copying the payloads. Integers are copied (they are
/// the payload); the list spine is rebuilt, which is the cost of a tree of
/// `Cow`s rather than a tree of references.
///
/// `AadPiece` is `#[non_exhaustive]`, so a variant this crate does not know
/// is cloned whole rather than refused: the view must be the same context,
/// and a clone is.
pub fn borrowed<'b>(piece: &'b AadPiece<'_>) -> AadPiece<'b> {
    match piece {
        AadPiece::Text(text) => AadPiece::Text(Cow::Borrowed(text.as_ref())),
        AadPiece::Bytes(bytes) => AadPiece::Bytes(Cow::Borrowed(bytes.as_ref())),
        AadPiece::U8(v) => AadPiece::U8(*v),
        AadPiece::U16(v) => AadPiece::U16(*v),
        AadPiece::U32(v) => AadPiece::U32(*v),
        AadPiece::U64(v) => AadPiece::U64(*v),
        AadPiece::U128(v) => AadPiece::U128(*v),
        AadPiece::I8(v) => AadPiece::I8(*v),
        AadPiece::I16(v) => AadPiece::I16(*v),
        AadPiece::I32(v) => AadPiece::I32(*v),
        AadPiece::I64(v) => AadPiece::I64(*v),
        AadPiece::I128(v) => AadPiece::I128(*v),
        AadPiece::List(parts) => AadPiece::List(parts.iter().map(borrowed).collect()),
        other => other.clone().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_encrypt::{nonempty, IntoAad, IntoPrfContext};
    use vitaminc_protected::Protected;

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    #[test]
    fn a_bare_string_is_the_flat_context() {
        let parsed = parse_context(s("users/age")).expect("flat context");
        assert_eq!(parsed.get(), &AadPiece::Text(Cow::Borrowed("users/age")));
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

    /// The borrowed view is the same context as the owned tree.
    #[test]
    fn the_borrowed_view_encodes_as_the_owned_tree() {
        let parsed = parse_context(FfiValue::Array(vec![
            s("users/age"),
            FfiValue::Array(vec![
                FfiValue::Bytes(Protected::new(b"k".to_vec())),
                FfiValue::Int64(-1),
            ]),
        ]))
        .expect("context");
        let owned = parsed.clone().into_inner();
        let view =
            NonEmpty::new(borrowed(parsed.get())).expect("a non-empty context borrows non-empty");
        assert_eq!(view.get(), &owned, "the view is a different tree");
        assert_eq!(
            view.clone().into_inner().into_aad().as_bytes(),
            owned.clone().into_aad().as_bytes(),
            "AAD bytes differ between the borrowed view and the owned tree"
        );
        assert_eq!(
            view.into_inner().into_prf_context().as_bytes(),
            owned.into_prf_context().as_bytes(),
            "PRF bytes differ between the borrowed view and the owned tree"
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

    /// `[x]` is `Some(x)` on the AAD, the descriptor and the PRF side
    /// (vitaminc 0.4.0 made the `Option` PRF context follow its parts view).
    #[test]
    fn a_one_element_list_is_some() {
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
        assert_eq!(
            list.into_prf_context().as_bytes(),
            some.into_prf_context().as_bytes(),
            "[x] and Some(x) share the PRF context"
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
