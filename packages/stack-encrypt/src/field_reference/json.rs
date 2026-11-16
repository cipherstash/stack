//! The JSON queries of a field that stores a JSON document.
//!
//! A field whose type stores a document ([`JsonQueries`]) has one field reference
//! method for each kind of JSON query:
//!
//! | Field reference method | What it finds | Returns |
//! | --- | --- | --- |
//! | [`contains(doc)`](FieldReference::contains), [`contained_by(doc)`](FieldReference::contained_by) | Rows whose document contains `doc`, or is contained by it (`@>`, `<@`) | [`JsonQueries::Query`] |
//! | [`at(path)`](FieldReference::at)`.eq(v)` | Rows with the scalar `v` at the path: containment of a one-entry document | [`JsonQueries::Query`] |
//! | `at(path).lt(v)`, `.lte`, `.gt`, `.gte` | Rows where the value at an ordered path compares with `v` | [`JsonQueries::LeafQuery`] |
//! | `at(path).between(lo, hi)` | Rows where the value at an ordered path lies between the bounds, both included | a pair of [`JsonQueries::LeafQuery`], low then high |
//! | `at(path).selector()` | The path's selector, which `->` and `ORDER BY` take | [`JsonQueries::Selector`] |
//! | [`elements(path)`](FieldReference::elements)`.eq(member, v).gt(member, v)` | Rows where one element of the array satisfies every condition together | [`JsonQueries::ElementsQuery`] |
//! | [`predicate(text)`](FieldReference::predicate) | Rows where a SQL/JSON path predicate is true | [`JsonQueries::PredicateQuery`] |
//! | [`children(path)`](FieldReference::children) | The node's token, which `json_tree_children` and `json_tree_child_count` take | [`JsonQueries::Token`] |
//!
//! The field reference supplies the field's column and its JSON options, which the
//! derive's `#[stash(json(..))]` attribute names, so a query derives under
//! the context and the options the stored documents were sealed under. A
//! scope the record lists is passed with [`scope`](JsonFieldQuery::scope), as
//! for any field query.
//!
//! For example, a customer's profile is stored under `customers/profile`,
//! ordering the age and each visit's time and place:
//!
//! ```
//! use serde_json::json;
//! use stack_encrypt::json::{JsonDocument, JsonPlaintext};
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::target::EncryptTarget;
//! use stack_encrypt::{EncryptInto, StackCipher};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct Customer {
//!     profile: JsonPlaintext,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = Customer, scope = "customers")]
//! struct EncryptedCustomer {
//!     #[stash(json(ordered = ["$.age", "$.visits[*].at", "$.visits[*].place"]))]
//!     profile: JsonDocument,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let stored: EncryptedCustomer = Customer {
//!     profile: json!({"name": "Ada", "age": 35, "visits": [{"place": "home", "at": 15}]}).into(),
//! }
//! .encrypt_into(&keyset)
//! .await?;
//!
//! // `col @> $1`: the stored document holds the needle.
//! let ada = EncryptedCustomer::PROFILE
//!     .contains(json!({"name": "Ada"}))
//!     .encrypt(&keyset)
//!     .await?;
//! assert!(ada.matches(stored.profile.selector_set()));
//!
//! // `(col -> $1) > $2`, with the selector the operand carries.
//! let older = EncryptedCustomer::PROFILE.at("$.age").gt(30).encrypt(&keyset).await?;
//! let age = EncryptedCustomer::PROFILE.at("$.age").selector().encrypt(&keyset).await?;
//! assert_eq!(older.selector(), age);
//!
//! // One visit that is at home and after 10.
//! let home = EncryptedCustomer::PROFILE
//!     .elements("$.visits[*]")
//!     .eq("place", "home")
//!     .gt("at", 10)
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(home.len(), 2);
//!
//! // `$.name` is not ordered, so an ordering there is refused before any
//! // key is requested.
//! assert!(EncryptedCustomer::PROFILE.at("$.name").gt("A").encrypt(&keyset).await.is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
//!
//! These do not compile: a JSON query of a field that stores no document
//! (`tests/ui/field_reference_json_on_a_scalar_field.rs`); an ordering of a boolean
//! or equality with a document (`tests/ui/field_reference_json_value_types.rs`);
//! `elements` with no condition
//! (`tests/ui/field_reference_elements_needs_a_condition.rs`); and a query of a
//! record that lists a scope, with no scope
//! (`tests/ui/field_reference_json_query_needs_its_scope.rs`).
//!
//! A path is JSONPath text. It is checked when the query is encrypted,
//! before any key is requested, by the rules the dynamic interface's JSON
//! operators apply, through the same code. A refusal comes in one of two
//! classes:
//!
//! - [`crate::Error::Term`], the JSON index's own refusals: an ordering at
//!   a path the field does not order
//!   ([`TermError::JsonPathNotOrdered`]), an ordering that names a
//!   position (`$.visits[2].at`, [`TermError::JsonOrderingAtPosition`]),
//!   a value an ordering cannot take, or a NaN or an infinity
//!   ([`TermError::JsonNumberNotFinite`]).
//! - [`crate::Error::Other`], the input's own shape, holding the dynamic
//!   interface's error and its reason: a position where the operand is a
//!   selector (`at("$.tags[1]").eq(..)`, `JsonPathPosition`), an
//!   `elements` path with no wildcard (`JsonPathNoWildcard`), a `children`
//!   path with one (`JsonPathWildcard`), or a predicate the grammar does
//!   not read (`JsonPredicateSyntax` and the rest). Its
//!   [`ErrorPayload`](crate::ErrorPayload) carries the reason.
//!
//! A value is typed: [`JsonScalar`] for equality, [`JsonOrdered`] (a number
//! or a string) for an ordering, and a whole document for containment. The
//! query holds each value in storage that is wiped when the query is
//! encrypted, refused or dropped.
use std::num::NonZeroU32;

use serde_json::Value;
use zeroize::Zeroizing;

use super::{FieldQuery, FieldReference, GivenScopes, Needs, Place, Ready, ScopeInput};
use crate::json::inputs::{
    self, elements_base, member_predicate, node_path, selector_path, Bounds, Compare, Derived,
    Input, Parsed, Under,
};
use crate::json::{FieldOptions, JsonOptions, JsonPlaintext, JsonQueries};
use crate::op::{AtPath, Between, ContainedBy, Contains, Eq, Gt, Gte, Lt, Lte};
use crate::sem::TermError;
use crate::target::Pending;
use crate::KeysetCipher;

/// The kind of a JSON query from a field reference that returns a path's selector:
/// [`ValueAt::selector`]. A type tag, with no values.
pub enum Selector {}

/// The kind of a JSON query from a field reference that holds an element-scoped
/// predicate: [`FieldReference::elements`]. A type tag, with no values.
pub enum ElementMatch {}

/// The kind of a JSON query from a field reference that holds a jsonpath predicate:
/// [`FieldReference::predicate`]. A type tag, with no values.
pub enum Predicate {}

/// The kind of a JSON query from a field reference that returns a node's token:
/// [`FieldReference::children`]. A type tag, with no values.
pub enum Children {}

/// A JSON query from a [`FieldReference`], of the kind `Op`, in the state `S`:
/// [`Needs`] its scope, or [`Ready`] for the keyset. Its paths, values and
/// predicate text are wiped when it is derived, refused or dropped.
///
/// `Op` is the query's kind: [`op::Contains`](Contains),
/// [`op::ContainedBy`](ContainedBy), an [`op::AtPath`](AtPath) of a
/// comparison, or one of this module's [`Selector`], [`ElementMatch`],
/// [`Predicate`] and [`Children`]. It decides what
/// [`encrypt`](JsonFieldQuery::encrypt) returns.
pub struct JsonFieldQuery<T, Op, S = Ready>(FieldQuery<T, Op, JsonInput, S>);

impl<T, Op, S> std::fmt::Debug for JsonFieldQuery<T, Op, S> {
    /// Names the query, its label and the fields that hold it; the paths
    /// and values are plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("JsonFieldQuery").field(&self.0).finish()
    }
}

impl<T, Op, C: GivenScopes> JsonFieldQuery<T, Op, Needs<C>> {
    /// Passes the scopes the query needs, and makes the query [`Ready`],
    /// as [`FieldQuery::scope`] does for a scalar field's query.
    pub fn scope(self, scope: C) -> JsonFieldQuery<T, Op, Ready> {
        JsonFieldQuery(self.0.scope(scope))
    }
}

/// What a JSON query from a field reference holds until it is encrypted: the field's
/// options and the query's path and values.
struct JsonInput {
    /// The options the field's `#[stash(json(..))]` names, or `None` for
    /// the options its type seals under.
    options: Option<FieldOptions>,
    body: Body,
}

/// A JSON query's paths and values, as the caller gave them.
enum Body {
    Document(Parsed),
    EqAt(Zeroizing<String>, Held),
    Ordering(Compare, Zeroizing<String>, Held),
    Between(Zeroizing<String>, Held, Held),
    Selector(Zeroizing<String>),
    Elements {
        path: Zeroizing<String>,
        bound: Option<NonZeroU32>,
        members: Vec<(Zeroizing<String>, Condition)>,
    },
    Predicate {
        text: Zeroizing<String>,
        vars: Parsed,
        bound: Option<NonZeroU32>,
    },
    Children(Zeroizing<String>),
}

impl Body {
    /// The checked input the operator derives from, under the field's
    /// options: every refusal the input can meet, met before any key is
    /// requested.
    fn into_input(self, options: &JsonOptions) -> Result<Input, crate::refusal::Error> {
        match self {
            Body::Document(document) => Ok(Input::Document(document)),
            Body::EqAt(path, value) => Input::eq_at(&path, value.checked()?),
            Body::Ordering(compare, path, value) => {
                Input::ordering(options, compare, &path, value.checked()?)
            }
            Body::Between(path, low, high) => {
                Input::between(options, &path, low.checked()?, high.checked()?)
            }
            Body::Selector(path) => Ok(Input::Selector(selector_path(&path)?)),
            Body::Elements {
                path,
                bound,
                members,
            } => {
                let base = elements_base(&path)?;
                let predicates = members
                    .into_iter()
                    .map(|(member, condition)| {
                        member_predicate(options, &base, &member, condition.checked()?)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Input::elements(bound.map(NonZeroU32::get), predicates)
            }
            Body::Predicate { text, vars, bound } => {
                Input::predicate(options, &text, &vars.0, bound.map(NonZeroU32::get))
            }
            Body::Children(path) => Ok(Input::Node(node_path(&path)?)),
        }
    }
}

/// A value moved into a query, or a number JSON cannot hold, which the
/// query refuses when it is encrypted.
enum Held {
    Value(Parsed),
    /// A NaN or an infinity: no JSON number, so no stored value is one.
    NotFinite,
}

impl Held {
    /// The value, or the refusal of a number JSON cannot hold
    /// ([`TermError::JsonNumberNotFinite`]).
    fn checked(self) -> Result<Parsed, crate::refusal::Error> {
        match self {
            Held::Value(value) => Ok(value),
            Held::NotFinite => Err(crate::refusal::Error::Cipher(
                TermError::JsonNumberNotFinite.into(),
            )),
        }
    }
}

/// One condition of an element predicate, as the caller gave it.
enum Condition {
    One(Compare, Held),
    Between(Held, Held),
}

impl Condition {
    fn checked(self) -> Result<Bounds, crate::refusal::Error> {
        Ok(match self {
            Condition::One(compare, value) => Bounds::One(compare, value.checked()?),
            Condition::Between(low, high) => Bounds::Between(low.checked()?, high.checked()?),
        })
    }
}

/// A value that equality at a path compares: a boolean, a number or a
/// string. Sealed.
pub trait JsonScalar: scalar_sealed::Sealed {
    /// The value as JSON: `None` for a NaN or an infinity, which no JSON
    /// number is.
    #[doc(hidden)]
    fn into_json(self) -> Option<Value>;
}

/// A value an ordering at a path compares: a number or a string, the
/// leaves the JSON index derives an ordering term for. Sealed.
pub trait JsonOrdered: JsonScalar {}

mod scalar_sealed {
    pub trait Sealed {}
}

macro_rules! json_values {
    (ordered: $($ordered:ty),+; scalar: $($scalar:ty),+;) => {
        $(
            impl scalar_sealed::Sealed for $ordered {}
            impl JsonScalar for $ordered {
                fn into_json(self) -> Option<Value> {
                    Some(Value::from(self))
                }
            }
            impl JsonOrdered for $ordered {}
        )+
        $(
            impl scalar_sealed::Sealed for $scalar {}
            impl JsonScalar for $scalar {
                fn into_json(self) -> Option<Value> {
                    Some(Value::from(self))
                }
            }
        )+
    };
}
json_values! {
    ordered: i8, i16, i32, i64, u8, u16, u32, u64, String, &str;
    scalar: bool;
}
impl scalar_sealed::Sealed for &String {}
impl JsonScalar for &String {
    fn into_json(self) -> Option<Value> {
        Some(Value::from(self.as_str()))
    }
}
impl JsonOrdered for &String {}

/// A finite `f64` is the JSON number it is. A NaN or an infinity is no
/// JSON number, and is refused when the query is encrypted.
impl scalar_sealed::Sealed for f64 {}
impl JsonScalar for f64 {
    fn into_json(self) -> Option<Value> {
        self.is_finite().then(|| Value::from(self))
    }
}
impl JsonOrdered for f64 {}

/// An `f32` is the number its shortest decimal form names, as it would be
/// written in a document: `0.1f32` is `0.1`, not the `f64` the bits widen
/// to, `0.10000000149011612`.
impl scalar_sealed::Sealed for f32 {}
impl JsonScalar for f32 {
    fn into_json(self) -> Option<Value> {
        if !self.is_finite() {
            return None;
        }
        self.to_string().parse::<f64>().ok().map(Value::from)
    }
}
impl JsonOrdered for f32 {}

/// A value moved into a query: wiped when the query is encrypted, refused
/// or dropped.
fn held(value: impl JsonScalar) -> Held {
    match value.into_json() {
        Some(value) => Held::Value(Parsed::of(value)),
        None => Held::NotFinite,
    }
}

/// A path's text, held in storage that is wiped on drop: a path names
/// keys, which are plaintext.
fn path_text(path: &str) -> Zeroizing<String> {
    Zeroizing::new(path.to_owned())
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P> FieldReference<W, T, C, P> {
    /// Rows whose document contains `document` (`col @> $1`): every member
    /// and element `document` holds is in the row's document. Exact, as
    /// PostgreSQL's `jsonb @>` is, across array elements included.
    pub fn contains(
        self,
        document: impl Into<JsonPlaintext>,
    ) -> JsonFieldQuery<T, Contains, C::Start> {
        self.json(Body::Document(Parsed::of(document.into().into_value())))
    }

    /// Rows whose document is contained by `document` (`col <@ $1`): the
    /// row's document holds nothing `document` does not. The operand is
    /// the one [`contains`](Self::contains) derives; the SQL operator says
    /// which way it compares.
    pub fn contained_by(
        self,
        document: impl Into<JsonPlaintext>,
    ) -> JsonFieldQuery<T, ContainedBy, C::Start> {
        self.json(Body::Document(Parsed::of(document.into().into_value())))
    }

    /// A query of the value at `path`: equality with
    /// [`eq`](ValueAt::eq), an ordering with [`lt`](ValueAt::lt) and the other
    /// comparisons, or the path's [`selector`](ValueAt::selector).
    pub fn at(self, path: &str) -> ValueAt<W, T, C, P> {
        ValueAt {
            reference: self,
            path: path_text(path),
        }
    }

    /// An element-scoped predicate on the array of elements at `path`, a
    /// path with a wildcard (`$.visits[*]`): rows where some one element
    /// satisfies every condition together, which two orderings at the same
    /// wildcard path cannot say. Give each condition with
    /// [`eq`](Elements::eq), [`lt`](Elements::lt) and the other
    /// comparisons, on a member of the element (`"place"`,
    /// `"address.city"`) whose full path the field orders.
    pub fn elements(self, path: &str) -> Elements<W, T, C, P> {
        Elements {
            reference: self,
            path: path_text(path),
        }
    }

    /// Rows where the SQL/JSON path predicate `text` is true, as
    /// `jsonb_path_match` decides it over the plaintext:
    /// `"$.age >= $min && exists($.visits[*] ? (@.place == \"home\"))"`.
    /// Name its variables with [`vars`](JsonFieldQuery::vars). The grammar and
    /// what each construct compiles to are the dynamic interface's `match`
    /// operator's. The predicate is compiled when the query is encrypted,
    /// before any key is requested.
    pub fn predicate(self, text: &str) -> JsonFieldQuery<T, Predicate, C::Start> {
        self.json(Body::Predicate {
            text: path_text(text),
            vars: Parsed::of(Value::Object(serde_json::Map::new())),
            bound: None,
        })
    }

    /// The token of the node at `path`, a path with no wildcard, which
    /// `eql_v4.json_tree_children` and `eql_v4.json_tree_child_count` take
    /// to find the node's children in every row.
    pub fn children(self, path: &str) -> JsonFieldQuery<T, Children, C::Start> {
        self.json(Body::Children(path_text(path)))
    }

    fn json<Op>(self, body: Body) -> JsonFieldQuery<T, Op, C::Start> {
        let options = self.json;
        JsonFieldQuery(self.held_query(JsonInput { options, body }, drop))
    }
}

/// A query of the value at a path, from [`FieldReference::at`]: one of the methods
/// below makes it a query.
pub struct ValueAt<W, T, C, P> {
    reference: FieldReference<W, T, C, P>,
    path: Zeroizing<String>,
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P> ValueAt<W, T, C, P> {
    /// Rows with the scalar `value` at the path: containment of the
    /// document that holds it there, so exact. At a path with a wildcard,
    /// rows where any element holds it. A position (`[2]`) is refused: a
    /// selector reads it as the wildcard.
    pub fn eq(self, value: impl JsonScalar) -> JsonFieldQuery<T, AtPath<Eq>, C::Start> {
        self.reference.json(Body::EqAt(self.path, held(value)))
    }

    /// Rows with a JSON `null` at the path: equality with `null`, which is
    /// containment of the document that holds it there. At a path with a
    /// wildcard, rows where any element is `null`. A row with no node at
    /// the path does not match: that is `SQL NULL`, not a JSON `null`.
    pub fn is_null(self) -> JsonFieldQuery<T, AtPath<Eq>, C::Start> {
        self.reference
            .json(Body::EqAt(self.path, Held::Value(Parsed::of(Value::Null))))
    }

    /// Rows where the value at the path is below `value`. The path must be
    /// one the field orders.
    pub fn lt(self, value: impl JsonOrdered) -> JsonFieldQuery<T, AtPath<Lt>, C::Start> {
        self.ordering(Compare::Lt, value)
    }

    /// Rows where the value at the path is at or below `value`.
    pub fn lte(self, value: impl JsonOrdered) -> JsonFieldQuery<T, AtPath<Lte>, C::Start> {
        self.ordering(Compare::Lte, value)
    }

    /// Rows where the value at the path is above `value`.
    pub fn gt(self, value: impl JsonOrdered) -> JsonFieldQuery<T, AtPath<Gt>, C::Start> {
        self.ordering(Compare::Gt, value)
    }

    /// Rows where the value at the path is at or above `value`.
    pub fn gte(self, value: impl JsonOrdered) -> JsonFieldQuery<T, AtPath<Gte>, C::Start> {
        self.ordering(Compare::Gte, value)
    }

    /// Rows where the value at the path is between `low` and `high`, both
    /// included. The query returns the two operands, low then high.
    pub fn between<V: JsonOrdered>(
        self,
        low: V,
        high: V,
    ) -> JsonFieldQuery<T, AtPath<Between>, C::Start> {
        self.reference
            .json(Body::Between(self.path, held(low), held(high)))
    }

    /// The path's selector, which `col -> $1` and an `ORDER BY` over
    /// `eql_v4.ord_term(col -> $1)` take. A position (`[2]`) is refused: a
    /// selector reads it as the wildcard.
    pub fn selector(self) -> JsonFieldQuery<T, Selector, C::Start> {
        self.reference.json(Body::Selector(self.path))
    }

    fn ordering<Op>(
        self,
        compare: Compare,
        value: impl JsonOrdered,
    ) -> JsonFieldQuery<T, Op, C::Start> {
        self.reference
            .json(Body::Ordering(compare, self.path, held(value)))
    }
}

/// An element-scoped predicate before its first condition, from
/// [`FieldReference::elements`]. Each method adds a condition and makes it a query,
/// to which more conditions can be added.
pub struct Elements<W, T, C, P> {
    reference: FieldReference<W, T, C, P>,
    path: Zeroizing<String>,
}

macro_rules! element_conditions {
    ($($(#[$doc:meta])* $method:ident => $compare:ident;)+) => {
        impl<W: Place, T: JsonQueries, C: ScopeInput, P> Elements<W, T, C, P> {
            $(
                $(#[$doc])*
                pub fn $method(
                    self,
                    member: &str,
                    value: impl JsonOrdered,
                ) -> JsonFieldQuery<T, ElementMatch, C::Start> {
                    self.first(member, Condition::One(Compare::$compare, held(value)))
                }
            )+
        }
        impl<T, S> JsonFieldQuery<T, ElementMatch, S> {
            $(
                $(#[$doc])*
                pub fn $method(self, member: &str, value: impl JsonOrdered) -> Self {
                    self.condition(member, Condition::One(Compare::$compare, held(value)))
                }
            )+
        }
    };
}
element_conditions! {
    /// The member equals `value`, as the ordering terms compare: text
    /// case- and accent-folded, numbers as 64-bit floats. Exact equality
    /// of any element is [`at(path).eq`](ValueAt::eq).
    eq => Eq;
    /// The member is below `value`.
    lt => Lt;
    /// The member is at or below `value`.
    lte => Lte;
    /// The member is above `value`.
    gt => Gt;
    /// The member is at or above `value`.
    gte => Gte;
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P> Elements<W, T, C, P> {
    /// The member lies between `low` and `high`, both included.
    pub fn between<V: JsonOrdered>(
        self,
        member: &str,
        low: V,
        high: V,
    ) -> JsonFieldQuery<T, ElementMatch, C::Start> {
        self.first(member, Condition::Between(held(low), held(high)))
    }

    fn first(
        self,
        member: &str,
        condition: Condition,
    ) -> JsonFieldQuery<T, ElementMatch, C::Start> {
        self.reference.json(Body::Elements {
            path: self.path,
            bound: None,
            members: vec![(path_text(member), condition)],
        })
    }
}

impl<T, S> JsonFieldQuery<T, ElementMatch, S> {
    /// The member lies between `low` and `high`, both included.
    pub fn between<V: JsonOrdered>(self, member: &str, low: V, high: V) -> Self {
        self.condition(member, Condition::Between(held(low), held(high)))
    }

    /// How many elements of each array the predicate reads: 64 unless
    /// named. A row whose array is longer is refused by the database, as a
    /// subtree read of it is.
    pub fn wildcard_bound(mut self, bound: NonZeroU32) -> Self {
        if let Some(JsonInput {
            body: Body::Elements { bound: held, .. },
            ..
        }) = self.0.value.as_mut()
        {
            *held = Some(bound);
        }
        self
    }

    fn condition(mut self, member: &str, condition: Condition) -> Self {
        if let Some(JsonInput {
            body: Body::Elements { members, .. },
            ..
        }) = self.0.value.as_mut()
        {
            members.push((path_text(member), condition));
        }
        self
    }
}

impl<T, S> JsonFieldQuery<T, Predicate, S> {
    /// The predicate's variables, one JSON object whose members the
    /// predicate names as `$name`: the `vars` `jsonb_path_match` takes.
    /// None by default. An object is required: anything else is refused
    /// when the query is encrypted.
    pub fn vars(mut self, vars: impl Into<JsonPlaintext>) -> Self {
        if let Some(JsonInput {
            body: Body::Predicate { vars: held, .. },
            ..
        }) = self.0.value.as_mut()
        {
            *held = Parsed::of(vars.into().into_value());
        }
        self
    }

    /// How many elements of each array the predicate's element-scoped
    /// conditions read: 64 unless named.
    pub fn wildcard_bound(mut self, bound: NonZeroU32) -> Self {
        if let Some(JsonInput {
            body: Body::Predicate { bound: held, .. },
            ..
        }) = self.0.value.as_mut()
        {
            *held = Some(bound);
        }
        self
    }
}

/// A refusal of the JSON input, as the crate reports it: a cipher error,
/// such as a term refusal, passes through; the input's own refusals are
/// boxed with their reason, as `dynamic::Planned` boxes them.
fn wrap(error: crate::refusal::Error) -> crate::Error {
    match error {
        crate::refusal::Error::Cipher(error) => error,
        other => crate::Error::Other(Box::new(other)),
    }
}

/// An operand that is not the one the query's kind derives: a bug here.
fn mismatched() -> crate::Error {
    crate::Error::Other("a JSON query derived an operand of another kind".into())
}

impl<T: JsonQueries, Op> JsonFieldQuery<T, Op, Ready> {
    /// Check the query under the field's options, or the options the
    /// field's type seals under when it names none, and derive its operand
    /// under the field's query context: the field reference's label, extended by the
    /// outer fields' contexts and the scopes.
    fn derive_json<'a, K: 'static>(
        &mut self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, Derived, K> {
        let Some(input) = self.0.value.take() else {
            unreachable!("a query holds its value until it is encrypted or dropped")
        };
        let scopes = self.0.extension();
        let options = match input
            .options
            .map_or_else(|| Ok(T::default_options()), |f| f())
        {
            Ok(options) => options,
            Err(error) => return Pending::failed(keyset, error.into()),
        };
        let checked = match input.body.into_input(&options) {
            Ok(checked) => checked,
            Err(error) => return Pending::failed(keyset, wrap(error)),
        };
        let under = Under::new(&self.0.label, scopes);
        match inputs::derive(keyset, &under, &options, checked) {
            Ok(pending) => pending,
            Err(error) => Pending::failed(keyset, wrap(error)),
        }
    }
}

macro_rules! json_encrypt {
    ($($(#[$doc:meta])* $op:ty => $output:ident, |$derived:ident| $convert:expr;)+) => {$(
        impl<T: JsonQueries> JsonFieldQuery<T, $op, Ready> {
            $(#[$doc])*
            ///
            /// The query is checked under the field's options before any
            /// key is requested, and its values are wiped when it is
            /// derived, refused or dropped. The operand is derived locally:
            /// it requests no key.
            pub fn encrypt<'a, K: 'static>(
                mut self,
                keyset: &'a KeysetCipher<'_, K>,
            ) -> Pending<'a, T::$output, K> {
                self.derive_json(keyset).try_map(|$derived| $convert)
            }
        }
    )+};
}
json_encrypt! {
    /// Derives the containment needle, as the field's type stores it.
    Contains => Query, |derived| match derived {
        Derived::Query(query) => T::query(query),
        _ => Err(mismatched()),
    };
    /// Derives the containment needle, as the field's type stores it.
    ContainedBy => Query, |derived| match derived {
        Derived::Query(query) => T::query(query),
        _ => Err(mismatched()),
    };
    /// Derives the needle of the document holding the value at the path.
    AtPath<Eq> => Query, |derived| match derived {
        Derived::Query(query) => T::query(query),
        _ => Err(mismatched()),
    };
    /// Derives the ordering operand: the path's selector and the value's
    /// ordering term.
    AtPath<Lt> => LeafQuery, |derived| match derived {
        Derived::Leaf(query) => T::leaf_query(query),
        _ => Err(mismatched()),
    };
    /// Derives the ordering operand: the path's selector and the value's
    /// ordering term.
    AtPath<Lte> => LeafQuery, |derived| match derived {
        Derived::Leaf(query) => T::leaf_query(query),
        _ => Err(mismatched()),
    };
    /// Derives the ordering operand: the path's selector and the value's
    /// ordering term.
    AtPath<Gt> => LeafQuery, |derived| match derived {
        Derived::Leaf(query) => T::leaf_query(query),
        _ => Err(mismatched()),
    };
    /// Derives the ordering operand: the path's selector and the value's
    /// ordering term.
    AtPath<Gte> => LeafQuery, |derived| match derived {
        Derived::Leaf(query) => T::leaf_query(query),
        _ => Err(mismatched()),
    };
    /// Derives the element-scoped predicate.
    ElementMatch => ElementsQuery, |derived| match derived {
        Derived::Elements(query) => T::elements_query(query),
        _ => Err(mismatched()),
    };
    /// Derives the compiled predicate.
    Predicate => PredicateQuery, |derived| match derived {
        Derived::Predicate(query) => T::predicate_query(query),
        _ => Err(mismatched()),
    };
    /// Derives the path's selector.
    Selector => Selector, |derived| match derived {
        Derived::Selector(selector) => T::selector(selector),
        _ => Err(mismatched()),
    };
    /// Derives the node's token.
    Children => Token, |derived| match derived {
        Derived::Node(key) => T::token(key),
        _ => Err(mismatched()),
    };
}

impl<T: JsonQueries> JsonFieldQuery<T, AtPath<Between>, Ready> {
    /// Derives the two ordering operands, low then high, under one
    /// context.
    ///
    /// The query is checked under the field's options before any key is
    /// requested, and its values are wiped when it is derived, refused or
    /// dropped. The operands are derived locally: they request no key.
    pub fn encrypt<'a, K: 'static>(
        mut self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, (T::LeafQuery, T::LeafQuery), K> {
        self.derive_json(keyset).try_map(|derived| match derived {
            Derived::Range(low, high) => Ok((T::leaf_query(low)?, T::leaf_query(high)?)),
            _ => Err(mismatched()),
        })
    }
}
