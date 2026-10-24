//! A context read from a binding's frame. See [`context`](context()).

use std::borrow::Cow;
use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Unexpected, Visitor};
use serde::Deserialize;

use super::{Error, Reason};
use crate::{ContextPiece, NonEmpty};

/// A context arrives from a binding as a frame and becomes a
/// [`ContextPiece`] tree: vitaminc's runtime form of a context, and the
/// *identity* of one. vitaminc's law (pinned there by quickcheck over every
/// built-in context type) is that a context's two derivations each equal the
/// same derivation of its parts view:
///
/// ```text
/// x.into_aad()         == x.into_context().into_aad()
/// x.into_prf_context() == x.into_context().into_prf_context()
/// ```
///
/// So a `#[derive(EncryptFrom)]` row sealed with
/// `encrypt_into_with_context(row, 7u64)`, which binds each field under
/// `(("users", "age"), 7u64)` — the inferred pair, extended — and a binding
/// that spells the same context as `[["users", "age"], 7u64]` agree byte for
/// byte on
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
/// as the transport frame allows
/// ([`MAX_DEPTH`](vitaminc_aead::frame::MAX_DEPTH) levels, counted
/// from the root of the frame); a deeper frame is refused before it is
/// read. Text and bytes with the same content are distinct contexts (UTF-8
/// versus bytes typed leaves) — the same distinction the Rust types make.
/// An integer's width is part of its identity, so it is read at the width
/// the frame carries, and only the four widths above are contexts.
/// Booleans, floats, null, objects, other integer widths, a scalar with a
/// logical type and passthroughs are not contexts.
///
/// # Which Rust contexts a list spells
///
/// * `["users", "age"]` is `nonempty!("users").with("age")`: a two-element
///   list is the pair. That is how a table and a column are spelled: two
///   parts, rendered `users/age` in the descriptor, never a joined string.
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
/// use stack_encrypt::dynamic::context;
/// use stack_encrypt::{nonempty, IntoAad};
///
/// // `[["users", "age"], 7u64]`, as a binding writes it.
/// let frame = vitaminc_aead_frame::serde::to_vec(&(("users", "age"), 7u64))?;
/// let parsed = context(&frame)?;
/// let typed = nonempty!("users").with("age").with(7u64);
/// assert_eq!(
///     parsed.into_inner().into_aad().as_bytes(),
///     typed.into_aad().as_bytes()
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`Error::Context`] for anything outside the shape above
/// ([`Reason::ContextKind`]), including bytes that are not one frame, and
/// for a context that renders empty ([`Reason::EmptyContext`]). It names no
/// field: the caller that knows the field names it ([`Error::in_field`]).
pub fn context(frame: &[u8]) -> Result<NonEmpty<ContextPiece<'static>>, Error> {
    let Context(piece) = vitaminc_aead_frame::serde::from_slice(frame)
        .map_err(|_| Error::bad_context(Reason::ContextKind))?;
    non_empty(piece)
}

/// A context tree, proven non-empty by vitaminc's rule.
pub(super) fn non_empty(
    piece: ContextPiece<'static>,
) -> Result<NonEmpty<ContextPiece<'static>>, Error> {
    NonEmpty::new(piece).map_err(|_| Error::bad_context(Reason::EmptyContext))
}

/// One context as serde reads it from a frame (see [`context`](context())).
/// A visitor rather than a derive: an untagged enum would buffer the value
/// through serde's own content type, which lets a text variant take bytes,
/// and would read an integer at whichever variant's width it fits first.
pub(super) struct Context(pub(super) ContextPiece<'static>);

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ContextVisitor).map(Context)
    }
}

struct ContextVisitor;

impl<'de> Visitor<'de> for ContextVisitor {
    type Value = ContextPiece<'static>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a context: a string, bytes, an i32, i64, u32 or u64, or a list of contexts")
    }

    fn visit_str<E>(self, text: &str) -> Result<Self::Value, E> {
        Ok(ContextPiece::Text(Cow::Owned(text.to_owned())))
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        Ok(ContextPiece::Bytes(Cow::Owned(bytes.to_vec())))
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E> {
        Ok(ContextPiece::I32(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(ContextPiece::I64(v))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E> {
        Ok(ContextPiece::U32(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(ContextPiece::U64(v))
    }

    // serde forwards the narrow widths to the 64-bit methods by default,
    // which would read a `u8` as a `u64` context: a different identity.
    fn visit_i8<E: de::Error>(self, v: i8) -> Result<Self::Value, E> {
        Err(E::invalid_type(Unexpected::Signed(v.into()), &self))
    }

    fn visit_i16<E: de::Error>(self, v: i16) -> Result<Self::Value, E> {
        Err(E::invalid_type(Unexpected::Signed(v.into()), &self))
    }

    fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
        Err(E::invalid_type(Unexpected::Unsigned(v.into()), &self))
    }

    fn visit_u16<E: de::Error>(self, v: u16) -> Result<Self::Value, E> {
        Err(E::invalid_type(Unexpected::Unsigned(v.into()), &self))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut parts = Vec::with_capacity(reserved(seq.size_hint()));
        while let Some(Context(part)) = seq.next_element()? {
            parts.push(part);
        }
        Ok(ContextPiece::List(parts))
    }
}

/// How many elements to reserve room for before reading a list or an
/// object a control frame declares `hint` of. The hint is the count the frame
/// declares, which nothing has checked against the bytes that follow: a few
/// bytes can declare four billion elements, which would abort the guest on
/// allocation. So at most [`RESERVED`] are reserved, and a longer list grows as
/// it is read.
pub(super) fn reserved(hint: Option<usize>) -> usize {
    hint.unwrap_or(0).min(RESERVED)
}

/// The most elements [`reserved`] reserves room for: more than a context or
/// a plan holds in practice.
const RESERVED: usize = 64;

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
    use crate::dynamic::test_frame::frame_of;
    use crate::dynamic::test_frame::Tree;
    use crate::{nonempty, Descriptor, IntoAad, IntoPrfContext};
    use vitaminc_aead_frame::serde::to_vec;

    fn s(value: &str) -> Tree {
        Tree::String(value.into())
    }

    /// The context `value` spells, read from its frame.
    fn ctx(value: Tree) -> Result<NonEmpty<ContextPiece<'static>>, Error> {
        context(&frame_of(&value))
    }

    /// `borrowed` is a view, so it must be the same context for every
    /// variant: one list holding each integer width, each byte-bearing
    /// piece, and a nested list is its own borrowed view. A variant this
    /// match forgot would fall to the cloning arm and still compare equal,
    /// so the test also pins that no payload was copied where a borrow was
    /// due — the text and bytes come back as `Cow::Borrowed`.
    #[test]
    fn a_borrowed_view_is_the_same_context_for_every_piece() {
        let owned = ContextPiece::List(vec![
            ContextPiece::Text(Cow::Owned("users/age".to_string())),
            ContextPiece::Bytes(Cow::Owned(vec![1, 2, 3])),
            ContextPiece::Encoded(Cow::Owned(vec![4, 5, 6])),
            ContextPiece::U8(8),
            ContextPiece::U16(16),
            ContextPiece::U32(32),
            ContextPiece::U64(64),
            ContextPiece::U128(128),
            ContextPiece::I8(-8),
            ContextPiece::I16(-16),
            ContextPiece::I32(-32),
            ContextPiece::I64(-64),
            ContextPiece::I128(-128),
            ContextPiece::List(vec![ContextPiece::Text(Cow::Owned("t".to_string()))]),
        ]);

        let view = borrowed(&owned);
        assert_eq!(view, owned, "the view is the same context");

        let ContextPiece::List(parts) = &view else {
            panic!("the view of a list is a list");
        };
        assert!(
            matches!(&parts[0], ContextPiece::Text(Cow::Borrowed(_))),
            "text is borrowed, not copied"
        );
        assert!(
            matches!(&parts[1], ContextPiece::Bytes(Cow::Borrowed(_))),
            "bytes are borrowed, not copied"
        );
        assert!(
            matches!(&parts[2], ContextPiece::Encoded(Cow::Borrowed(_))),
            "encoded bytes are borrowed, not copied"
        );
    }

    #[test]
    fn a_bare_string_is_the_flat_context() {
        let parsed = ctx(s("users/age")).expect("flat context");
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
        let parsed =
            ctx(Tree::Array(vec![s("users/age"), Tree::UInt64(7)])).expect("extended context");
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
        let parsed = ctx(Tree::Array(vec![s("users"), s("age")])).expect("a pair");
        assert_eq!(
            Descriptor::of(parsed.into_inner()).as_str(),
            "users/age",
            "the list renders its parts joined by `/`"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users").with("age")).as_str(),
            "users/age",
            "the tuple renders the same descriptor"
        );
        let parsed = ctx(Tree::Array(vec![
            Tree::Array(vec![s("users"), s("age")]),
            Tree::UInt64(7),
        ]))
        .expect("an extended pair");
        assert_eq!(
            Descriptor::of(parsed.into_inner()).as_str(),
            "(users/age)/7u64"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users").with("age").with(7u64)).as_str(),
            "(users/age)/7u64",
            "`with` nests to the left, as the list does"
        );
    }

    #[test]
    fn a_nested_list_encodes_as_the_nested_tuple() {
        let parsed = ctx(Tree::Array(vec![
            s("users/age"),
            Tree::Array(vec![s("t"), Tree::Int32(-3)]),
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
        let parsed = ctx(Tree::Array(vec![
            s("users/age"),
            Tree::Array(vec![Tree::Bytes(b"k".to_vec()), Tree::Int64(-1)]),
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
        let nested = ctx(Tree::Array(vec![
            Tree::Array(vec![s("a"), Tree::UInt64(7)]),
            s("eu"),
        ]))
        .expect("nested")
        .into_inner();
        let flat = ctx(Tree::Array(vec![s("a"), Tree::UInt64(7), s("eu")]))
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
        let list = ctx(Tree::Array(vec![Tree::UInt64(7)]))
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
        let list = ctx(Tree::Array(vec![s("a")])).expect("list");
        let bare = ctx(s("a")).expect("bare");
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
        let text = ctx(s("ab")).expect("text").into_inner();
        let bytes = ctx(Tree::Bytes(b"ab".to_vec()))
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
            ("empty bytes", Tree::Bytes(Vec::new())),
            ("an empty list", Tree::Array(vec![])),
            ("a list of one empty string", Tree::Array(vec![s("")])),
            (
                "a list of empties",
                Tree::Array(vec![Tree::Array(vec![]), s("")]),
            ),
        ] {
            assert!(
                matches!(ctx(empty), Err(Error::Context { .. })),
                "{label} is empty by the tuple rule and must be refused"
            );
        }
        for (label, non_empty) in [
            ("a zero integer", Tree::UInt64(0)),
            (
                "an empty string beside an integer",
                Tree::Array(vec![s(""), Tree::Int32(0)]),
            ),
            (
                "a nested non-empty list",
                Tree::Array(vec![Tree::Array(vec![s("x")])]),
            ),
        ] {
            assert!(
                ctx(non_empty).is_ok(),
                "{label} carries bytes and must be accepted"
            );
        }
    }

    #[test]
    fn non_context_values_are_encoding_errors() {
        for (label, bad) in [
            ("null", Tree::Null),
            ("undefined", Tree::Undefined),
            ("a boolean", Tree::Bool(true)),
            ("a float32", Tree::Float32(1.0)),
            ("a float64", Tree::Float64(1.0)),
            ("an object", Tree::Object(vec![("k".to_string(), s("v"))])),
            (
                "a list with a boolean in it",
                Tree::Array(vec![s("ok"), Tree::Bool(false)]),
            ),
        ] {
            assert!(
                matches!(ctx(bad), Err(Error::Context { .. })),
                "{label} is not a context and must be refused"
            );
        }
    }

    /// An integer's width is its identity, so only the four widths a
    /// context takes are read, each at its own width; the others are
    /// refused rather than widened.
    #[test]
    fn an_integer_is_read_at_its_own_width() {
        let read = |frame: Vec<u8>| context(&frame).map(NonEmpty::into_inner);
        assert_eq!(read(to_vec(&7i32).unwrap()).unwrap(), ContextPiece::I32(7));
        assert_eq!(read(to_vec(&7i64).unwrap()).unwrap(), ContextPiece::I64(7));
        assert_eq!(read(to_vec(&7u32).unwrap()).unwrap(), ContextPiece::U32(7));
        assert_eq!(read(to_vec(&7u64).unwrap()).unwrap(), ContextPiece::U64(7));
        for (label, frame) in [
            ("an i8", to_vec(&7i8).unwrap()),
            ("an i16", to_vec(&7i16).unwrap()),
            ("a u8", to_vec(&7u8).unwrap()),
            ("a u16", to_vec(&7u16).unwrap()),
            ("an i128", to_vec(&7i128).unwrap()),
            ("a u128", to_vec(&7u128).unwrap()),
            ("a u8 in a list", to_vec(&("users", 7u8)).unwrap()),
        ] {
            assert!(
                matches!(
                    read(frame),
                    Err(Error::Context {
                        reason: Reason::ContextKind,
                        ..
                    })
                ),
                "{label} is not a context"
            );
        }
    }

    /// What a frame declares is reserved only up to a bound, whatever it
    /// declares.
    #[test]
    fn a_declared_count_reserves_at_most_the_bound() {
        assert_eq!(reserved(None), 0);
        assert_eq!(reserved(Some(3)), 3);
        assert_eq!(reserved(Some(RESERVED)), RESERVED);
        assert_eq!(reserved(Some(u32::MAX as usize)), RESERVED);
    }

    /// A list that declares more parts than its frame holds is refused
    /// when the parts run out, without reserving room for the count it
    /// declared: four billion parts would abort the guest on allocation.
    #[test]
    fn a_list_that_declares_more_parts_than_it_holds_is_refused() {
        let mut bytes = vec![vitaminc_aead::frame::ARRAY];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            context(&bytes),
            Err(Error::Context {
                reason: Reason::ContextKind,
                ..
            })
        ));
    }

    /// Bytes that are not one frame are not a context.
    #[test]
    fn bytes_that_are_not_a_frame_are_refused() {
        for bytes in [&[][..], &[0xff, 1, 2], &to_vec(&"a").unwrap()[..2]] {
            assert!(matches!(
                context(bytes),
                Err(Error::Context {
                    reason: Reason::ContextKind,
                    ..
                })
            ));
        }
    }
}
