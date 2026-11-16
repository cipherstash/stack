//! A field type that stores a JSON document: sealed under the JSON index's
//! options, and queried from the field reference.
//!
//! A record field of such a type takes its options from the derive's
//! field attribute, `#[stash(json(ordered = ["$.age"]))]`. The derive seals
//! the field through [`JsonTarget`] under those options, and gives the
//! field's reference the same options, so a query derives under the options
//! the stored documents were sealed under. The field reference's JSON queries
//! return the field type's own query types ([`JsonQueries`]): the engine's
//! for [`JsonDocument`], and EQL's for the `eql-bindings` document type.
use stack_kms::MaybeSend;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

use super::{
    JsonDocument, JsonElementsQuery, JsonLeafQuery, JsonOptions, JsonPlaintext, JsonPredicateQuery,
    JsonQuery, JsonSelector, JsonSubtreeKey,
};
use crate::sem::TermError;
use crate::target::{json_document, EncryptTarget, Encryption, Owned, Pending};
use crate::Error;

/// A target that stores a JSON document, sealed under the JSON index's
/// options: which paths carry an ordering term, and whether the root is
/// sealed.
///
/// [`EncryptTarget::encryption`] seals under the default options, which
/// order no path. A record field marked `#[stash(json(..))]` is sealed
/// through this trait instead, under the options the attribute names.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not store a JSON document",
    label = "`#[stash(json(..))]` is on a field of this type",
    note = "`#[stash(json(..))]` names the JSON index's options, so it goes on a field whose type stores a JSON document, such as `JsonDocument` or `eql_bindings::v4::json_tree::JsonTreeDocument`"
)]
pub trait JsonTarget<S: Zeroize>: EncryptTarget<S> {
    /// The description of the value's encryption under `options`, over a
    /// borrowed plaintext.
    fn json_encryption<'s, K: 'static>(
        options: JsonOptions,
    ) -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's;

    /// The description of the value's encryption under `options`, over an
    /// owned plaintext. By default it guards the plaintext, runs the
    /// borrowed description over it, and wipes it, as
    /// [`EncryptTarget::owned_encryption`] does.
    fn json_owned_encryption<'s, K: 'static>(
        options: JsonOptions,
    ) -> Encryption<'s, S, Self, K, Self::ContextInput, Owned>
    where
        S: 's,
    {
        Encryption::from_build(
            Self::json_encryption::<K>(options.clone()).shapes(),
            move |source: S, cipher, context| {
                let guarded = Protected::new(source);
                let pending =
                    cipher.run(Self::json_encryption(options), guarded.risky_ref(), context);
                drop(guarded);
                pending
            },
        )
    }
}

/// A document under the options: the JSON index's layout and terms, under
/// the caller's context.
impl JsonTarget<JsonPlaintext> for JsonDocument {
    fn json_encryption<'s, K: 'static>(
        options: JsonOptions,
    ) -> Encryption<'s, JsonPlaintext, Self, K, Self::ContextInput>
    where
        JsonPlaintext: 's,
    {
        json_document(options)
            .project(JsonPlaintext::value)
            .accepting()
    }
}

/// A nullable document field: a `Some` is sealed under the options, and a
/// `None` stores nothing, as [`EncryptTarget`] for an `Option` does.
impl<S: Zeroize, T: JsonTarget<S> + MaybeSend> JsonTarget<Option<S>> for Option<T> {
    fn json_encryption<'s, K: 'static>(
        options: JsonOptions,
    ) -> Encryption<'s, Option<S>, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        Encryption::from_build(
            T::json_encryption::<K>(options.clone()).shapes(),
            move |source: &'s Option<S>, cipher, context: T::ContextInput| match source {
                Some(value) => cipher
                    .run(T::json_encryption(options), value, context)
                    .map(Some),
                None => Pending::ready(cipher, Ok(None)),
            },
        )
    }

    fn json_owned_encryption<'s, K: 'static>(
        options: JsonOptions,
    ) -> Encryption<'s, Option<S>, Self, K, Self::ContextInput, Owned>
    where
        S: 's,
    {
        Encryption::from_build(
            T::json_owned_encryption::<K>(options.clone()).shapes(),
            move |source: Option<S>, cipher, context: T::ContextInput| {
                // Building the target's declaration can panic, so the value
                // stays guarded until the declaration exists. The
                // declaration then takes the value over, and wipes it.
                let guarded = Protected::new(source);
                let description = T::json_owned_encryption(options);
                match guarded.risky_unwrap() {
                    Some(value) => cipher.run(description, value, context).map(Some),
                    None => Pending::ready(cipher, Ok(None)),
                }
            },
        )
    }
}

/// What the JSON queries of a field of this type return.
///
/// A field reference has the JSON queries ([`contains`], [`at`], [`elements`],
/// [`predicate`], [`children`] and the rest) when the field's type
/// implements this trait. The engine derives each operand as its own type,
/// and the field's type converts it into the type it stores queries as:
/// for the engine's [`JsonDocument`], the engine's types themselves; for
/// EQL's document type, the EQL query types a parameter binds as.
///
/// [`contains`]: crate::field_reference::FieldReference::contains
/// [`at`]: crate::field_reference::FieldReference::at
/// [`elements`]: crate::field_reference::FieldReference::elements
/// [`predicate`]: crate::field_reference::FieldReference::predicate
/// [`children`]: crate::field_reference::FieldReference::children
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not store a JSON document, so its field reference has no JSON queries",
    label = "this field's type is `{Self}`",
    note = "the JSON queries (`contains`, `at`, `elements`, `predicate`, `children`) belong to a field whose type stores a JSON document, such as `JsonDocument` or `eql_bindings::v4::json_tree::JsonTreeDocument`"
)]
pub trait JsonQueries {
    /// A containment needle: `contains`, `contained_by` and `at(path).eq`.
    type Query: MaybeSend + 'static;
    /// An ordering at a path: `at(path).lt` and the other comparisons, and
    /// each bound of `at(path).between`.
    type LeafQuery: MaybeSend + 'static;
    /// An element-scoped predicate: `elements(path)`.
    type ElementsQuery: MaybeSend + 'static;
    /// A compiled jsonpath predicate: `predicate(text)`.
    type PredicateQuery: MaybeSend + 'static;
    /// A path's selector, which `->` takes: `at(path).selector()`.
    type Selector: MaybeSend + 'static;
    /// One node's token, which the child functions take: `children(path)`.
    type Token: MaybeSend + 'static;

    /// The options a field of this type is sealed under when its record
    /// names none with `#[stash(json(..))]`: the options its
    /// [`EncryptTarget::encryption`] seals under. A query of such a field
    /// derives under them, so they must be the same, or the field's
    /// orderings are refused and its tokens match nothing. The defaults,
    /// which order no path, unless the type seals under others.
    fn default_options() -> JsonOptions {
        JsonOptions::default()
    }

    /// The containment needle the engine derived, as this type stores it.
    ///
    /// # Errors
    ///
    /// When the conversion fails.
    fn query(query: JsonQuery) -> Result<Self::Query, Error>;
    /// The ordering operand the engine derived, as this type stores it.
    ///
    /// # Errors
    ///
    /// When the conversion fails.
    fn leaf_query(query: JsonLeafQuery) -> Result<Self::LeafQuery, Error>;
    /// The element-scoped predicate the engine derived, as this type stores
    /// it.
    ///
    /// # Errors
    ///
    /// When the conversion fails.
    fn elements_query(query: JsonElementsQuery) -> Result<Self::ElementsQuery, Error>;
    /// The compiled predicate the engine derived, as this type stores it.
    ///
    /// # Errors
    ///
    /// When the conversion fails.
    fn predicate_query(query: JsonPredicateQuery) -> Result<Self::PredicateQuery, Error>;
    /// The selector the engine derived, as this type stores it.
    ///
    /// # Errors
    ///
    /// When the conversion fails.
    fn selector(selector: JsonSelector) -> Result<Self::Selector, Error>;
    /// The key of a path that names one node, which holds that node's one
    /// token, as this type stores the token.
    ///
    /// # Errors
    ///
    /// When the conversion fails.
    fn token(key: JsonSubtreeKey) -> Result<Self::Token, Error>;
}

/// The engine's own types. The token is the key of the path, which holds
/// the node's one token ([`JsonSubtreeKey::tokens`]).
impl JsonQueries for JsonDocument {
    type Query = JsonQuery;
    type LeafQuery = JsonLeafQuery;
    type ElementsQuery = JsonElementsQuery;
    type PredicateQuery = JsonPredicateQuery;
    type Selector = JsonSelector;
    type Token = JsonSubtreeKey;
    fn query(query: JsonQuery) -> Result<JsonQuery, Error> {
        Ok(query)
    }
    fn leaf_query(query: JsonLeafQuery) -> Result<JsonLeafQuery, Error> {
        Ok(query)
    }
    fn elements_query(query: JsonElementsQuery) -> Result<JsonElementsQuery, Error> {
        Ok(query)
    }
    fn predicate_query(query: JsonPredicateQuery) -> Result<JsonPredicateQuery, Error> {
        Ok(query)
    }
    fn selector(selector: JsonSelector) -> Result<JsonSelector, Error> {
        Ok(selector)
    }
    fn token(key: JsonSubtreeKey) -> Result<JsonSubtreeKey, Error> {
        Ok(key)
    }
}

/// A nullable document field is queried as a present one is. A row whose
/// field is `None` stores no document, so no query matches it.
impl<T: JsonQueries> JsonQueries for Option<T> {
    fn default_options() -> JsonOptions {
        T::default_options()
    }
    type Query = T::Query;
    type LeafQuery = T::LeafQuery;
    type ElementsQuery = T::ElementsQuery;
    type PredicateQuery = T::PredicateQuery;
    type Selector = T::Selector;
    type Token = T::Token;
    fn query(query: JsonQuery) -> Result<T::Query, Error> {
        T::query(query)
    }
    fn leaf_query(query: JsonLeafQuery) -> Result<T::LeafQuery, Error> {
        T::leaf_query(query)
    }
    fn elements_query(query: JsonElementsQuery) -> Result<T::ElementsQuery, Error> {
        T::elements_query(query)
    }
    fn predicate_query(query: JsonPredicateQuery) -> Result<T::PredicateQuery, Error> {
        T::predicate_query(query)
    }
    fn selector(selector: JsonSelector) -> Result<T::Selector, Error> {
        T::selector(selector)
    }
    fn token(key: JsonSubtreeKey) -> Result<T::Token, Error> {
        T::token(key)
    }
}

/// The options a `#[stash(json(..))]` field names, as the derive builds
/// them: refused paths are an error the field's encryption and its queries
/// meet before any key is requested.
#[doc(hidden)]
pub type FieldOptions = fn() -> Result<JsonOptions, TermError>;

/// The borrowed description of a `#[stash(json(..))]` field: `T`'s
/// encryption under `options`, or, for options the attribute names wrongly,
/// a refusal before any key is requested. For the derive.
#[doc(hidden)]
pub fn seal_field<'s, T, S, K>(
    options: Result<JsonOptions, TermError>,
) -> Encryption<'s, S, T, K, T::ContextInput>
where
    T: JsonTarget<S>,
    S: Zeroize + 's,
    K: 'static,
{
    match options {
        Ok(options) => T::json_encryption(options),
        Err(error) => Encryption::failed(error.into()),
    }
}

/// The owned description of a `#[stash(json(..))]` field, as
/// [`seal_field`]. A refusal wipes the plaintext it is handed. For the
/// derive.
#[doc(hidden)]
pub fn seal_field_owned<'s, T, S, K>(
    options: Result<JsonOptions, TermError>,
) -> Encryption<'s, S, T, K, T::ContextInput, Owned>
where
    T: JsonTarget<S>,
    S: Zeroize + 's,
    K: 'static,
{
    match options {
        Ok(options) => T::json_owned_encryption(options),
        Err(error) => Encryption::from_build(Vec::new(), move |mut source: S, cipher, _| {
            source.zeroize();
            Pending::failed(cipher, error.into())
        }),
    }
}
