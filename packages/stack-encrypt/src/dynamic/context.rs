//! An [`FfiValue`] read as an encryption context. See [`context`](context()).

use std::borrow::Cow;

use vitaminc_aead_value::FfiValue;
use vitaminc_protected::Controlled;

use super::Error;
use crate::{ContextPiece, NonEmpty};

/// A context arrives from a binding as a value and becomes a [`ContextPiece`]
/// tree: vitaminc's runtime form of a context, and the *identity* of one.
/// vitaminc's law (pinned there by quickcheck over every built-in context
/// type) is that a context's two derivations each equal the same derivation
/// of its parts view:
///
/// ```text
/// x.into_aad()         == x.into_context().into_aad()
/// x.into_prf_context() == x.into_context().into_prf_context()
/// ```
///
/// So a `#[derive(EncryptFrom)]` row sealed with
/// `encrypt_into_with_context(row, 7u64)`, which binds each field under
/// `("users/age", 7u64)` — a `NonEmpty<(&str, u64)>` — and a binding that
/// spells the same context as `["users/age", 7u64]` agree byte for byte on
/// the AAD (the ciphertext binding and the ZeroKMS descriptor rendered from
/// its parts) *and* on the PRF context (the index terms' domain separation).
/// Nothing is re-derived here: the tree is handed to vitaminc's own impls.
///
/// # Shape
///
/// ```text
/// context := <string> | <bytes> | <i32> | <i64> | <u32> | <u64> | [ context, ... ]
/// ```
///
/// A bare string is one text part. An array is a list, and may nest as deep
/// as the transport codec allows
/// ([`MAX_DEPTH`](vitaminc_aead_value::transport::MAX_DEPTH) levels, counted
/// from the root of the encoded value); a deeper value is refused by the
/// codec before this module sees it. Text and bytes with the same content
/// are distinct contexts (UTF-8 versus bytes typed leaves) — the same
/// distinction the Rust types make. Booleans, floats, null, undefined,
/// objects and passthroughs are not contexts.
///
/// # Which Rust contexts a list spells
///
/// * `["users/age", 7u64]` is `nonempty!("users/age").with(7u64)`: a
///   two-element list is the pair.
/// * `NonEmpty::with` nests to the **left**: `nonempty!("a").with(7u64)
///   .with("eu")` is `(("a", 7u64), "eu")`, spelled `[["a", 7u64], "eu"]`.
///   A flat three-element list is a different context (a three-part PAE)
///   that no `.with()` chain produces.
/// * `[x]` is `Some(x)` and `[]` is `None`, on both derivations. A
///   one-element list is *not* the bare part: it is PAE-framed, the bare
///   part is not.
///
/// # Emptiness
///
/// [`context`](context()) returns a [`NonEmpty`], proven once here by
/// vitaminc's own rule for the tree: an empty string or byte string is
/// empty, an integer never is, and a list is empty when every part is (so
/// `[]` and `[""]` are, `["", 7]` is not) — the rule its `Option` and tuple
/// impls follow.
///
/// # Examples
///
/// The list a binding spells and the tuple a Rust caller writes are one
/// context:
///
/// ```
/// use stack_encrypt::dynamic::{context, FfiValue};
/// use stack_encrypt::{nonempty, IntoAad};
///
/// let parsed = context(FfiValue::Array(vec![
///     FfiValue::String("users/age".into()),
///     FfiValue::UInt64(7),
/// ]))?;
/// let typed = nonempty!("users/age").with(7u64);
/// assert_eq!(
///     parsed.into_inner().into_aad().as_bytes(),
///     typed.into_aad().as_bytes()
/// );
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Context`] for anything outside the shape above, and for a
/// context that renders empty.
pub fn context(value: FfiValue) -> Result<NonEmpty<ContextPiece<'static>>, Error> {
    NonEmpty::new(piece_of(value)?).map_err(|_| Error::Context)
}

fn piece_of(value: FfiValue) -> Result<ContextPiece<'static>, Error> {
    Ok(match value {
        // Valid UTF-8 by `Utf8String`'s construction invariant; checked
        // rather than assumed because this is boundary code. The payload
        // moves out of its `Protected` rather than being copied: a context
        // is not secret, and the copy would only be wiped and freed.
        FfiValue::String(s) => ContextPiece::Text(Cow::Owned(
            String::from_utf8(s.into_inner().risky_unwrap()).map_err(|_| Error::Context)?,
        )),
        FfiValue::Bytes(bytes) => ContextPiece::Bytes(Cow::Owned(bytes.risky_unwrap())),
        FfiValue::Int32(v) => ContextPiece::I32(v),
        FfiValue::Int64(v) => ContextPiece::I64(v),
        FfiValue::UInt32(v) => ContextPiece::U32(v),
        FfiValue::UInt64(v) => ContextPiece::U64(v),
        // Nesting depth is bounded by the codec's `MAX_DEPTH` before the
        // value reaches here.
        FfiValue::Array(items) => ContextPiece::List(
            items
                .into_iter()
                .map(piece_of)
                .collect::<Result<Vec<_>, Error>>()?,
        ),
        FfiValue::Null
        | FfiValue::Undefined
        | FfiValue::Bool(_)
        | FfiValue::Float32(_)
        | FfiValue::Float64(_)
        | FfiValue::Object(_)
        | FfiValue::Passthrough(_) => return Err(Error::Context),
    })
}

/// A view of a context tree that borrows its text and bytes, so a context
/// parsed and proven once can be handed to every output of every row without
/// copying the payloads. Integers are copied (they are the payload); the
/// list spine is rebuilt, which is the cost of a tree of `Cow`s rather than
/// a tree of references.
///
/// [`ContextPiece`] is `#[non_exhaustive]`, so a variant this crate does not
/// know is cloned whole rather than refused: the view must be the same
/// context, and a clone is.
pub fn borrowed<'b>(piece: &'b ContextPiece<'_>) -> ContextPiece<'b> {
    match piece {
        ContextPiece::Text(text) => ContextPiece::Text(Cow::Borrowed(text.as_ref())),
        ContextPiece::Bytes(bytes) => ContextPiece::Bytes(Cow::Borrowed(bytes.as_ref())),
        ContextPiece::U8(v) => ContextPiece::U8(*v),
        ContextPiece::U16(v) => ContextPiece::U16(*v),
        ContextPiece::U32(v) => ContextPiece::U32(*v),
        ContextPiece::U64(v) => ContextPiece::U64(*v),
        ContextPiece::U128(v) => ContextPiece::U128(*v),
        ContextPiece::I8(v) => ContextPiece::I8(*v),
        ContextPiece::I16(v) => ContextPiece::I16(*v),
        ContextPiece::I32(v) => ContextPiece::I32(*v),
        ContextPiece::I64(v) => ContextPiece::I64(*v),
        ContextPiece::I128(v) => ContextPiece::I128(*v),
        ContextPiece::Encoded(bytes) => ContextPiece::Encoded(Cow::Borrowed(bytes.as_ref())),
        ContextPiece::List(parts) => ContextPiece::List(parts.iter().map(borrowed).collect()),
        other => other.clone().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nonempty, Descriptor, IntoAad, IntoPrfContext};
    use vitaminc_protected::Protected;

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    #[test]
    fn a_bare_string_is_the_flat_context() {
        let parsed = context(s("users/age")).expect("flat context");
        assert_eq!(
            parsed.get(),
            &ContextPiece::Text(Cow::Borrowed("users/age")),
            "a bare string is one text part, not a one-element list"
        );
        assert_eq!(
            parsed.into_inner().into_aad().as_bytes(),
            "users/age".into_aad().as_bytes(),
            "the AAD is the string's own, unframed"
        );
    }

    #[test]
    fn a_list_encodes_as_the_tuple_on_both_sides() {
        let parsed = context(FfiValue::Array(vec![s("users/age"), FfiValue::UInt64(7)]))
            .expect("extended context");
        let tuple = nonempty!("users/age").with(7u64);
        assert_eq!(
            parsed.clone().into_inner().into_aad().as_bytes(),
            tuple.into_aad().as_bytes(),
            "a two-element list is the pair on the AAD side"
        );
        assert_eq!(
            parsed.into_inner().into_prf_context().as_bytes(),
            tuple.into_prf_context().as_bytes(),
            "a two-element list is the pair on the PRF side"
        );
    }

    #[test]
    fn a_list_renders_the_descriptor_the_tuple_does() {
        let parsed = context(FfiValue::Array(vec![s("users/age"), FfiValue::UInt64(7)]))
            .expect("extended context");
        assert_eq!(
            Descriptor::of(parsed.into_inner()).as_str(),
            "users/age|7u64",
            "the list renders its parts joined by `|`"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users/age").with(7u64)).as_str(),
            "users/age|7u64",
            "the tuple renders the same descriptor"
        );
    }

    #[test]
    fn a_nested_list_encodes_as_the_nested_tuple() {
        let parsed = context(FfiValue::Array(vec![
            s("users/age"),
            FfiValue::Array(vec![s("t"), FfiValue::Int32(-3)]),
        ]))
        .expect("nested context");
        let tuple = ("users/age", ("t", -3i32));
        assert_eq!(
            parsed.clone().into_inner().into_aad().as_bytes(),
            tuple.into_aad().as_bytes(),
            "a nested list is the nested tuple on the AAD side"
        );
        assert_eq!(
            parsed.into_inner().into_prf_context().as_bytes(),
            tuple.into_prf_context().as_bytes(),
            "a nested list is the nested tuple on the PRF side"
        );
    }

    /// The borrowed view is the same context as the owned tree.
    #[test]
    fn the_borrowed_view_encodes_as_the_owned_tree() {
        let parsed = context(FfiValue::Array(vec![
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
        let nested = context(FfiValue::Array(vec![
            FfiValue::Array(vec![s("a"), FfiValue::UInt64(7)]),
            s("eu"),
        ]))
        .expect("nested")
        .into_inner();
        let flat = context(FfiValue::Array(vec![s("a"), FfiValue::UInt64(7), s("eu")]))
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
        let list = context(FfiValue::Array(vec![FfiValue::UInt64(7)]))
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
        let list = context(FfiValue::Array(vec![s("a")])).expect("list");
        let bare = context(s("a")).expect("bare");
        assert_ne!(
            list.clone().into_inner().into_aad().as_bytes(),
            bare.clone().into_inner().into_aad().as_bytes(),
            "[x] is PAE-framed and x is not, so their AAD differs"
        );
        assert_ne!(
            list.into_inner().into_prf_context().as_bytes(),
            bare.into_inner().into_prf_context().as_bytes(),
            "[x] is PAE-framed and x is not, so their PRF context differs"
        );
    }

    /// Text and bytes are typed leaves, so the same content is two contexts
    /// on both sides (vitaminc 0.5; before it they shared AAD bytes).
    #[test]
    fn text_and_bytes_are_distinct_contexts_on_both_sides() {
        let text = context(s("ab")).expect("text").into_inner();
        let bytes = context(FfiValue::Bytes(Protected::new(b"ab".to_vec())))
            .expect("bytes")
            .into_inner();
        assert_ne!(
            text.clone().into_aad().as_bytes(),
            bytes.clone().into_aad().as_bytes(),
            "text and bytes of the same content are distinct AAD"
        );
        assert_ne!(
            text.into_prf_context().as_bytes(),
            bytes.into_prf_context().as_bytes(),
            "text and bytes are distinct PRF encodings"
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
            assert!(
                matches!(context(empty), Err(Error::Context)),
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
                context(non_empty).is_ok(),
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
            assert!(
                matches!(context(bad), Err(Error::Context)),
                "{label} is not a context and must be refused"
            );
        }
    }
}
