//! The JSON queries of a field that stores a JSON document.
//!
//! A field whose type stores a document ([`JsonQueries`]) has one field
//! reference method for each kind of JSON query:
//!
//! | Field reference method | What it finds | Returns |
//! | --- | --- | --- |
//! | [`contains(doc)`](FieldReference::contains), [`contained_by(doc)`](FieldReference::contained_by) | Rows whose document contains `doc`, or is contained by it (`@>`, `<@`) | [`JsonQueries::Query`] |
//! | [`at()`](FieldReference::at)`.age().eq(v)` | Rows with the scalar `v` at the path: containment of a one-entry document | [`JsonQueries::Query`] |
//! | `at().age().lt(v)`, `.lte`, `.gt`, `.gte` | Rows where the value at the path compares with `v` | [`JsonQueries::LeafQuery`] |
//! | `at().age().between(lo, hi)` | Rows where the value at the path lies between the bounds, both included | a pair of [`JsonQueries::LeafQuery`], low then high |
//! | `at().age().selector()` | The path's selector, which `->` and `ORDER BY` take | [`JsonQueries::Selector`] |
//! | [`elements()`](FieldReference::elements)`.visits().place().eq(v).and().at().gt(v)` | Rows where one element of the array satisfies every condition together | [`JsonQueries::ElementsQuery`] |
//! | [`predicate(text)`](FieldReference::predicate) | Rows where a SQL/JSON path predicate is true | [`JsonQueries::PredicateQuery`] |
//! | [`children(path)`](FieldReference::children) | The node's token, which `json_tree_children` and `json_tree_child_count` take | [`JsonQueries::Token`] |
//!
//! The field reference supplies the field's column and its JSON options,
//! which the derive's `#[stash(json(..))]` attribute names, so a query
//! derives under the context and the options the stored documents were
//! sealed under. A scope the record lists is passed with
//! [`scope`](JsonFieldQuery::scope), as for any field query.
//!
//! # Declared paths
//!
//! The attribute names each path the field declares and the type of the
//! values at it, under one of two keys:
//!
//! - `ordered = { "$.age": u32, "$.visits[*].place": String }`: paths whose
//!   numbers and strings carry an ordering term, so they are compared with
//!   equality and the orderings. A number type or `String`
//!   ([`JsonPathType`]).
//! - `paths = { "$.name": String, "$.vip": bool }`: paths compared with
//!   equality alone. They add nothing to the field's options, so the field
//!   stores no ordering term for them. A boolean, a number type or `String`
//!   ([`JsonScalarType`]).
//!
//! The derive parses every path when it compiles the record, and generates
//! one method for each:
//!
//! - under [`at()`](FieldReference::at), one per path, named after the
//!   path's keys: `$.age` is `age()`, `$.visits[*].at` is `visits_at()`.
//!   Each returns a [`DeclaredPath`] of the path's type, whose orderings
//!   (`lt`, `gt`, `between` and the rest) compile for an `ordered` path
//!   only.
//! - under [`elements()`](FieldReference::elements), one per array whose
//!   elements have an ordered member: `$.visits[*]` is `visits()`. That
//!   array's members are methods in turn, named after the keys below the
//!   array: `place()`, `at()`. Each returns an [`ElementMember`] of the
//!   member's type. [`and()`](JsonFieldQuery::and) after a condition gives
//!   the same array's members again. A member under `paths` has none: an
//!   element-scoped condition compares ordering terms, even for equality.
//!
//! So the compiler refuses a path or a member the field does not declare,
//! a value of another type, an ordering of a path declared for equality,
//! and a member of another array. The `stack-encrypt-derive` attribute
//! reference gives the naming rule.
//!
//! For example, a customer's profile is stored under `customers/profile`,
//! ordering the age and each visit's time and place, and declaring the name
//! for equality:
//!
//! ```
//! use serde_json::json;
//! use stack_encrypt::json::{JsonDocument, JsonPlaintext};
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
//!     #[stash(json(
//!         ordered = { "$.age": u32, "$.visits[*].at": u64, "$.visits[*].place": String },
//!         paths = { "$.name": String },
//!     ))]
//!     profile: JsonDocument,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
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
//! // `col @> $1` at a path declared for equality alone.
//! let named = EncryptedCustomer::PROFILE.at().name().eq("Ada").encrypt(&keyset).await?;
//! assert!(named.matches(stored.profile.selector_set()));
//!
//! // `(col -> $1) > $2`, with the selector the operand carries.
//! let older = EncryptedCustomer::PROFILE.at().age().gt(30).encrypt(&keyset).await?;
//! let age = EncryptedCustomer::PROFILE.at().age().selector().encrypt(&keyset).await?;
//! assert_eq!(older.selector(), age);
//!
//! // One visit that is at home and after 10.
//! let home = EncryptedCustomer::PROFILE
//!     .elements()
//!     .visits()
//!     .place().eq("home")
//!     .and().at().gt(10)
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(home.len(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
//!
//! These do not compile: a path or a member the field does not declare
//! (`tests/ui/field_reference_json_undeclared_path.rs`); an ordering of a
//! path declared under `paths`
//! (`tests/ui/field_reference_json_equality_path.rs`); a value of another
//! type, at a path or for a member, or an `f32`
//! (`tests/ui/field_reference_json_value_types.rs`); a member of another
//! array (`tests/ui/field_reference_json_member_of_another_array.rs`);
//! `elements` with no condition
//! (`tests/ui/field_reference_elements_needs_a_condition.rs`); a predicate
//! variable that is not a scalar
//! (`tests/ui/field_reference_predicate_var_takes_a_scalar.rs`); a JSON query
//! of a field that stores no document
//! (`tests/ui/field_reference_json_on_a_scalar_field.rs`); and a query of a
//! record that lists a scope, with no scope
//! (`tests/ui/field_reference_json_query_needs_its_scope.rs`).
//!
//! # Paths as text
//!
//! A filter built at run time, from a user's input, names its paths as
//! text: [`at_text_path("$.age")`](FieldReference::at_text_path) and
//! [`elements_text_path("$.visits[*]")`](FieldReference::elements_text_path),
//! whose conditions name each member as text (`.eq("place", "home")`). So do
//! [`children`](FieldReference::children) and a field that declares no paths.
//! A typed query and a text query derive the same operand for the same path
//! and value.
//!
//! A path given as text is JSONPath, and is checked when the query is
//! encrypted, before any key is requested, by the rules the dynamic
//! interface's JSON operators apply, through the same code. A refusal comes
//! in one of two classes:
//!
//! - [`crate::Error::Term`], the JSON index's own refusals: an ordering at
//!   a path the field does not order
//!   ([`TermError::JsonPathNotOrdered`]), an ordering that names a
//!   position (`$.visits[2].at`, [`TermError::JsonOrderingAtPosition`]),
//!   a value an ordering cannot take, or a NaN or an infinity
//!   ([`TermError::JsonNumberNotFinite`]).
//! - [`crate::Error::Input`], the input's own shape, holding the dynamic
//!   interface's error and its [`Reason`](crate::refusal::Reason): a
//!   position where the operand is a selector (`at_text_path("$.tags[1]").eq(..)`,
//!   `JsonPathPosition`), an `elements_text_path` path with no wildcard
//!   (`JsonPathNoWildcard`), a `children` path with one
//!   (`JsonPathWildcard`), or a predicate the grammar does not read
//!   (`JsonPredicateSyntax` and the rest). Its code and its
//!   [`ErrorPayload`](crate::ErrorPayload) are the ones the dynamic
//!   interface reports for the same input.
//!
//! A typed path can meet only the value refusals: the derive refused every
//! other mistake when it compiled the record.
//!
//! A value is typed: [`JsonScalar`] for equality, [`JsonOrdered`] (a number
//! or a string) for an ordering, and a whole document for containment. A
//! declared path takes the type it declares ([`PathValue`]). The query holds
//! each value in storage that is wiped when the query is encrypted, refused
//! or dropped.
use std::marker::PhantomData;
use std::num::NonZeroU32;

use serde_json::Value;
use zeroize::Zeroizing;

use super::{FieldQuery, FieldReference, GivenScopes, Needs, Place, Ready, ScopeInput};
use crate::json::inputs::{
    self, elements_base, member_predicate, node_path, selector_path, Bounds, Compare, Derived,
    Input, Parsed, Under,
};
use crate::json::{FieldOptions, JsonOptions, JsonPlaintext, JsonQueries, JsonSubtreeKey};
use crate::op::{AtPath, Between, ContainedBy, Contains, Eq, Gt, Gte, Lt, Lte};
use crate::sem::TermError;
use crate::target::Pending;
use crate::KeysetCipher;

#[doc(hidden)]
pub mod predicate_checks;

/// A SQL/JSON path predicate on a document field, checked when the program
/// compiles and sent as written when it runs.
///
/// ```text
/// predicate!(FIELD_REFERENCE, "PREDICATE", name = value, …)
/// ```
///
/// The first argument is a document field's reference, such as
/// `EncryptedCustomer::PROFILE`, or one reached through an outer record
/// with [`field`](crate::FieldReference::field). The second is the
/// predicate's text, a string literal in the grammar
/// [`predicate(text)`](FieldReference::predicate) reads. Then each variable
/// the text names as `$name`: `name = value`, a local variable's name alone
/// for `name = name`, or `"any name" = value` for a `$"any name"` that is
/// not a Rust identifier. Each value is evaluated once, in the order given,
/// and moved into the query: a local given by its name alone is moved, as
/// [`var`](JsonFieldQuery::var) takes its value, so pass `name.clone()` or
/// `name.as_str()` to keep a `String`.
///
/// It returns what `predicate(text)` returns, with each variable given by
/// [`var`](JsonFieldQuery::var): a query whose
/// [`scope`](JsonFieldQuery::scope), [`wildcard_bound`](JsonFieldQuery::wildcard_bound)
/// and [`encrypt`](JsonFieldQuery::encrypt) work as they do there, and
/// whose operand is the one `predicate(text)` and the dynamic interface's
/// `match` operator derive for the same text and values.
///
/// The compiler refuses, at the predicate or at the variable:
///
/// - text the grammar does not read, and a construct the JSON index cannot
///   answer, with the construct and its byte offset;
/// - a variable the text uses and that is not given, one given and not
///   used, and one given twice;
/// - a path the field does not declare, under `ordered = {..}` or
///   `paths = {..}`; an ordering of a path declared under `paths`; and a
///   condition, in a filter of more than one, on a member its array does
///   not order (such a filter compares each member by its ordering term;
///   a filter of one equality is containment at the member's path, which
///   any declared path answers);
/// - a value of another type than the path's: a variable's value, a
///   literal in the text (`$.age > "x"`), a number literal the path's type
///   does not hold (`$.age > 1.5`, `$.age >= -1` and `$.age == 99999999999`
///   for a `u32`; an `f64` path takes any number), and an ordering's
///   `true`, `false` or `null`.
///
/// So every path the text names must be declared. A predicate on a path
/// the field does not declare, or one built at run time from a user's
/// input, is [`predicate(text)`](FieldReference::predicate), which checks
/// the same rules when the query is encrypted. A JSON `null` is the
/// literal `null` in the text (`$.note == null`); a variable cannot be
/// one here, but can with [`var_null`](JsonFieldQuery::var_null).
///
/// For example, a café keeps each customer's profile encrypted under
/// `customers/profile`, ordering the age and each visit's time and place,
/// and declaring the name for equality. It looks for Ada's profile if she
/// is 30 or more and once visited from home after 10 o'clock:
///
/// ```
/// use serde_json::json;
/// use stack_encrypt::json::{JsonDocument, JsonPlaintext};
/// use stack_encrypt::target::EncryptTarget;
/// use stack_encrypt::{predicate, EncryptInto, StackCipher};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// struct Customer {
///     profile: JsonPlaintext,
/// }
///
/// #[derive(EncryptTarget)]
/// #[stash(struct = Customer, scope = "customers")]
/// struct EncryptedCustomer {
///     #[stash(json(
///         ordered = { "$.age": u32, "$.visits[*].at": u64, "$.visits[*].place": String },
///         paths = { "$.name": String },
///     ))]
///     profile: JsonDocument,
/// }
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
/// let stored: EncryptedCustomer = Customer {
///     profile: json!({"name": "Ada", "age": 35, "visits": [{"place": "home", "at": 15}]}).into(),
/// }
/// .encrypt_into(&keyset)
/// .await?;
///
/// let min_age: u32 = 30;
/// let after: u64 = 10;
/// // `col @@ $1`, which `eql_v4.json_tree_match` evaluates.
/// let regulars = predicate!(
///     EncryptedCustomer::PROFILE,
///     r#"$.name == "Ada" && $.age >= $min_age && exists($.visits[*] ? (@.place == "home" && @.at > $after))"#,
///     min_age,
///     after,
/// )
/// .encrypt(&keyset)
/// .await?;
///
/// // The operand `predicate(text)` derives for the same text and values.
/// let from_text = EncryptedCustomer::PROFILE
///     .predicate(r#"$.name == "Ada" && $.age >= $min_age && exists($.visits[*] ? (@.place == "home" && @.at > $after))"#)
///     .var("min_age", min_age)
///     .var("after", after)
///     .encrypt(&keyset)
///     .await?;
/// // An equality is a containment needle, which sends its selectors in a
/// // random order: compare the two with every selector set (`sv`) sorted.
/// fn sorted(value: &mut serde_json::Value) {
///     match value {
///         serde_json::Value::Object(map) => {
///             for (key, inner) in map.iter_mut() {
///                 if let (true, serde_json::Value::Array(items)) = (key == "sv", &mut *inner) {
///                     items.sort_by_key(|item| item.to_string());
///                 }
///                 sorted(inner);
///             }
///         }
///         serde_json::Value::Array(items) => items.iter_mut().for_each(sorted),
///         _ => {}
///     }
/// }
/// let (mut regulars, mut from_text) = (serde_json::to_value(&regulars)?, serde_json::to_value(&from_text)?);
/// sorted(&mut regulars);
/// sorted(&mut from_text);
/// assert_eq!(regulars, from_text);
/// # let _ = stored;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// These do not compile, each with a message that names the mistake
/// (`tests/ui/predicate_*.rs`): `"$.agee >= $min"` (no such path),
/// `"$.name > \"A\""` (a path declared for equality alone),
/// `min = "thirty"` for `$.age` (a `u32` path), `"$.age >= $min"` with no
/// `min`, `limit = 5` that the text does not use, and
/// `"$.age like_regex \"^3\""` (a construct the index cannot answer).
#[macro_export]
macro_rules! predicate {
    ($($input:tt)*) => {
        $crate::field_reference::json::predicate_checks::predicate_with_crate!($crate; $($input)*)
    };
}

/// The kind of a JSON query from a field reference that returns a path's selector:
/// [`ValueAt::selector`]. A type tag, with no values.
pub enum Selector {}

/// The kind of a JSON query from a field reference that holds an
/// element-scoped predicate on the array `A`: an array the field declares,
/// from [`FieldReference::elements`], or [`TextPaths`] for an array named as
/// text, from [`FieldReference::elements_text_path`]. A type tag, with no
/// values. A typed array's conditions and a text array's are different
/// types, so one query does not mix them.
pub struct ElementMatch<A = TextPaths>(std::convert::Infallible, PhantomData<fn() -> A>);

/// The paths of a field that declares none: a field reference's default.
/// A document field with no `#[stash(json(ordered = {..}))]` paths names its
/// paths as text, with [`at_text_path`](FieldReference::at_text_path) and
/// [`elements_text_path`](FieldReference::elements_text_path). A type tag,
/// with no values.
pub enum TextPaths {}

/// The paths a document field declares, as types: implemented by the type
/// the derive generates for each field whose `#[stash(json(ordered = {..}))]`
/// names paths, and the fifth type parameter of that field's reference.
///
/// [`At`](Self::At) has one method per declared path and
/// [`Elements`](Self::Elements) one per declared array; each is generic over
/// the field reference's own parameters, so a field reached through an
/// outer record ([`FieldReference::field`]) has the same methods. For
/// generated code: write a field's paths in its attribute.
#[diagnostic::on_unimplemented(
    message = "this field declares no JSON paths, so its reference has no typed `at()` or `elements()`",
    label = "a field reference whose paths are `{Self}`",
    note = "declare the paths on the field, as `#[stash(json(ordered = {{ \"$.age\": u32 }}, paths = {{ \"$.name\": String }}))]`, or name a path as text with `at_text_path(\"$.age\")` or `elements_text_path(\"$.visits[*]\")`"
)]
pub trait DocumentPaths: Sized {
    /// What [`FieldReference::at`] returns: one method per declared path.
    type At<W, T, C, P>;
    /// What [`FieldReference::elements`] returns: one method per declared
    /// array whose elements have an ordered member.
    type Elements<W, T, C, P>;
    /// The accessors of the declared paths.
    #[doc(hidden)]
    fn at<W, T, C, P>(reference: FieldReference<W, T, C, P, Self>) -> Self::At<W, T, C, P>;
    /// The accessors of the declared arrays.
    #[doc(hidden)]
    fn elements<W, T, C, P>(
        reference: FieldReference<W, T, C, P, Self>,
    ) -> Self::Elements<W, T, C, P>;
}

/// One array a document field declares, as a type: implemented by the type
/// the derive generates for the array, whose methods are the array's
/// ordered members. [`and`](JsonFieldQuery::and) uses it to give the members
/// of the array an element predicate is on, so a condition on a member of
/// another array cannot be written. For generated code.
pub trait ElementArray {
    /// The array's members, with the predicate `Q` they add a condition to.
    type Members<Q>;
    /// The members of this array, adding to `query`.
    #[doc(hidden)]
    fn members<Q>(query: Q) -> Self::Members<Q>;
}

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
        vars: Vec<(Zeroizing<String>, Held)>,
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
                let vars = variables(vars)?;
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
///
/// There is no `f32`. serde_json widens an `f32` to the `f64` its bits
/// name when it builds a document (`0.1f32` is stored as
/// `0.10000000149011612`), and a query cannot know whether the stored
/// document was built that way or holds the decimal the `f32` prints as.
/// So pass the `f64` the document holds: `f64::from(x)` for a document
/// built from `x` through serde_json (`json!`, `to_value`).
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a JSON scalar",
    label = "a `{Self}`",
    note = "equality at a path and a predicate variable take a boolean, an integer, an `f64` or a string. There is no `f32`: pass `f64::from(x)`. To ask about an object or an array, use `contains`"
)]
pub trait JsonScalar: scalar_sealed::Sealed {
    /// The value as JSON: `None` for a NaN or an infinity, which no JSON
    /// number is.
    #[doc(hidden)]
    fn into_json(self) -> Option<Value>;
}

/// A value an ordering at a path compares: a number or a string, the
/// leaves the JSON index derives an ordering term for. Sealed.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a value an ordering compares",
    label = "a `{Self}`",
    note = "an ordering at a path takes an integer, an `f64` or a string; ask for a boolean or a null with equality at the path (`eq`, `is_null`)"
)]
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

/// A type a declared path holds: the type an entry of
/// `#[stash(json(paths = {..}))]` names, which equality compares: a boolean,
/// `i8` to `i64`, `u8` to `u64`, `f64` and `String`. Sealed.
///
/// There is no `f32`, for the reason [`JsonScalar`] gives: declare `f64` and
/// query with `f64::from(x)`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a type a declared path can hold",
    label = "the type a `paths = {{..}}` entry declares",
    note = "a declared path holds a boolean, a number or a string: declare `bool`, `i8` to `i64`, `u8` to `u64`, `f64` or `String`. For a float held as `f32`, declare `f64` and query with `f64::from(x)`"
)]
pub trait JsonScalarType: JsonScalar + scalar_type_sealed::Sealed {}

mod scalar_type_sealed {
    pub trait Sealed {}
}

/// A type an ordered path holds: the type an entry of
/// `#[stash(json(ordered = {..}))]` names. A number or a string, the leaves
/// the JSON index derives an ordering term for: `i8` to `i64`, `u8` to
/// `u64`, `f64` and `String`. Sealed.
///
/// There is no `f32`, for the reason [`JsonScalar`] gives: declare `f64` and
/// query with `f64::from(x)`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a type an ordered path can hold",
    label = "the type an `ordered = {{..}}` entry declares",
    note = "an ordered path holds a number or a string: declare `i8` to `i64`, `u8` to `u64`, `f64` or `String`. For a boolean, declare the path under `paths = {{..}}`, which equality compares. For a float held as `f32`, declare `f64` and query with `f64::from(x)`"
)]
pub trait JsonPathType: JsonOrdered + JsonScalarType + path_type_sealed::Sealed {}

mod path_type_sealed {
    pub trait Sealed {}
}

macro_rules! path_types {
    ($($ty:ty),+) => {$(
        impl path_type_sealed::Sealed for $ty {}
        impl JsonPathType for $ty {}
        impl scalar_type_sealed::Sealed for $ty {}
        impl JsonScalarType for $ty {}
    )+};
}
path_types!(i8, i16, i32, i64, u8, u16, u32, u64, f64, String);
impl scalar_type_sealed::Sealed for bool {}
impl JsonScalarType for bool {}

/// A value a declared path of type `V` takes: a `V`, or for a `String` path
/// a `&str` or a `&String` too. Sealed.
#[diagnostic::on_unimplemented(
    message = "this path holds `{V}`, and `{Self}` is not one",
    label = "a `{Self}`",
    note = "a declared path takes the type its `ordered = {{..}}` or `paths = {{..}}` entry names; a `String` path takes a `&str` or a `&String` too"
)]
pub trait PathValue<V>: JsonScalar + path_value_sealed::Sealed<V> {}

mod path_value_sealed {
    pub trait Sealed<V> {}
}

impl<V: JsonScalarType> path_value_sealed::Sealed<V> for V {}
impl<V: JsonScalarType> PathValue<V> for V {}
impl path_value_sealed::Sealed<String> for &str {}
impl PathValue<String> for &str {}
impl path_value_sealed::Sealed<String> for &String {}
impl PathValue<String> for &String {}

/// The kind of a declared path that an entry of `ordered = {..}` names:
/// its leaves carry an ordering term, and its accessor has equality and the
/// orderings. A type tag, with no values.
pub enum OrderedPath {}

/// The kind of a declared path that an entry of `paths = {..}` names: its
/// accessor has equality (`eq`, `is_null`) and the selector, and its leaves
/// carry only what any leaf carries, with no ordering term. A type tag,
/// with no values.
pub enum EqualityPath {}

/// A declared path's kind that has the orderings: [`OrderedPath`]. Sealed.
#[diagnostic::on_unimplemented(
    message = "this path is not ordered: declare it under `ordered` to compare it",
    label = "an ordering of a path declared under `paths`",
    note = "a path under `paths = {{..}}` is compared with `eq` and `is_null`; one under `ordered = {{..}}` with the orderings too, and its values carry an ordering term"
)]
pub trait OrderedPathKind: ordered_path_kind_sealed::Sealed {}

mod ordered_path_kind_sealed {
    pub trait Sealed {}
}

impl ordered_path_kind_sealed::Sealed for OrderedPath {}
impl OrderedPathKind for OrderedPath {}

/// A value moved into a query: wiped when the query is encrypted, refused
/// or dropped.
fn held(value: impl JsonScalar) -> Held {
    match value.into_json() {
        Some(value) => Held::Value(Parsed::of(value)),
        None => Held::NotFinite,
    }
}

/// The predicate's variables as the one object `jsonb_path_match` takes,
/// wiped when it drops. A name given twice is refused, as a repeated member
/// of that object is, and so is a number JSON cannot hold: both before any
/// key is requested.
fn variables(vars: Vec<(Zeroizing<String>, Held)>) -> Result<Parsed, crate::refusal::Error> {
    let mut object = Parsed::of(Value::Object(serde_json::Map::new()));
    for (mut name, value) in vars {
        let Value::Object(map) = &mut object.0 else {
            unreachable!("built as an object")
        };
        if map.contains_key(name.as_str()) {
            return Err(crate::refusal::Error::bad_source(
                crate::refusal::Reason::JsonDuplicateKey,
            ));
        }
        let _ = map.insert(std::mem::take(&mut *name), value.checked()?.take());
    }
    Ok(object)
}

/// A path's text, held in storage that is wiped on drop: a path names
/// keys, which are plaintext.
fn path_text(path: &str) -> Zeroizing<String> {
    Zeroizing::new(path.to_owned())
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P, D> FieldReference<W, T, C, P, D> {
    /// Rows whose document contains `document` (`col @> $1`): every member
    /// and element `document` holds is in the row's document. Exact, as
    /// PostgreSQL's `jsonb @>` is, across array elements included.
    ///
    /// A NaN or an infinity never reaches this query as a number: serde_json
    /// stores either as `null` when it builds a `Value` (`json!`,
    /// `to_value`, `Value::from`), so `json!({"score": f64::NAN})` asks for
    /// rows whose `score` is `null`. The engine cannot tell. Check a
    /// computed float before building the document, or query it with
    /// a path's `eq` ([`DeclaredPath::eq`], [`ValueAt::eq`]), which refuses
    /// one.
    pub fn contains(
        self,
        document: impl Into<JsonPlaintext>,
    ) -> JsonFieldQuery<T, Contains, C::Start> {
        self.json(Body::Document(Parsed::of(document.into().into_value())))
    }

    /// Rows whose document is contained by `document` (`col <@ $1`): the
    /// row's document holds nothing `document` does not. The operand is
    /// the one [`contains`](Self::contains) derives; the SQL operator says
    /// which way it compares. A NaN or an infinity in `document` is `null`,
    /// as in [`contains`](Self::contains).
    pub fn contained_by(
        self,
        document: impl Into<JsonPlaintext>,
    ) -> JsonFieldQuery<T, ContainedBy, C::Start> {
        self.json(Body::Document(Parsed::of(document.into().into_value())))
    }

    /// The paths the field declares, one method each: `at().age()` for
    /// `$.age`. Each returns a [`DeclaredPath`], whose methods are the
    /// queries of the value at the path: equality, the orderings, and the
    /// path's selector. A field that declares no paths has no `at()`: name
    /// its path as text with [`at_text_path`](Self::at_text_path).
    pub fn at(self) -> D::At<W, T, C, P>
    where
        D: DocumentPaths,
    {
        D::at(self)
    }

    /// The arrays the field declares whose elements have an ordered member,
    /// one method each: `elements().visits()` for `$.visits[*]`. An
    /// array's methods are its members (`place()`), and a condition on one
    /// starts an element-scoped predicate: rows where some one element
    /// satisfies every condition together, which two orderings at the same
    /// wildcard path cannot say. A field that declares no paths has no
    /// `elements()`: name its array as text with
    /// [`elements_text_path`](Self::elements_text_path).
    pub fn elements(self) -> D::Elements<W, T, C, P>
    where
        D: DocumentPaths,
    {
        D::elements(self)
    }

    /// A query of the value at `path`, JSONPath text checked when the
    /// query is encrypted: for a path a program builds at run time, from a
    /// user's filter. Equality with [`eq`](ValueAt::eq), an ordering with
    /// [`lt`](ValueAt::lt) and the other comparisons, or the path's
    /// [`selector`](ValueAt::selector). A path the field declares has a
    /// method under [`at`](Self::at), which the compiler checks.
    pub fn at_text_path(self, path: &str) -> ValueAt<W, T, C, P> {
        ValueAt {
            reference: self.untyped(),
            path: path_text(path),
        }
    }

    /// An element-scoped predicate on the array of elements at `path`,
    /// JSONPath text with a wildcard (`$.visits[*]`) checked when the query
    /// is encrypted: for an array a program names at run time. Give each
    /// condition with [`eq`](Elements::eq), [`lt`](Elements::lt) and the
    /// other comparisons, on a member of the element named as text
    /// (`"place"`, `"address.city"`) whose full path the field orders. An
    /// array the field declares has a method under
    /// [`elements`](Self::elements), which the compiler checks.
    pub fn elements_text_path(self, path: &str) -> Elements<W, T, C, P> {
        Elements {
            reference: self.untyped(),
            path: path_text(path),
        }
    }

    /// Rows where the SQL/JSON path predicate `text` is true, as
    /// `jsonb_path_match` decides it over the plaintext:
    /// `"$.age >= $min && exists($.visits[*] ? (@.place == \"home\"))"`.
    /// Name its variables with [`var`](JsonFieldQuery::var). The grammar and
    /// what each construct compiles to are the dynamic interface's `match`
    /// operator's. The predicate is compiled when the query is encrypted,
    /// before any key is requested.
    pub fn predicate(self, text: &str) -> JsonFieldQuery<T, Predicate, C::Start> {
        self.json(Body::Predicate {
            text: path_text(text),
            vars: Vec::new(),
            bound: None,
        })
    }

    /// The token of the node at `path`, a path with no wildcard, which
    /// `eql_v4.json_tree_children` and `eql_v4.json_tree_child_count` take
    /// to find the node's children in every row. For a [`JsonDocument`]
    /// field it is the [`JsonSubtreeKey`] that holds the token, which also
    /// opens each entry `json_tree_children` returns, one child at a time,
    /// checked against the node at `path`
    /// ([`JsonSubtreeKey::open_child`]). For a field of another type,
    /// [`encrypt_keyed`](JsonFieldQuery::encrypt_keyed) gives the token
    /// and that key from one derivation.
    ///
    /// [`JsonDocument`]: crate::json::JsonDocument
    /// [`JsonSubtreeKey::open_child`]: crate::json::JsonSubtreeKey::open_child
    pub fn children(self, path: &str) -> JsonFieldQuery<T, Children, C::Start> {
        self.json(Body::Children(path_text(path)))
    }

    /// This field reference with its declared paths forgotten: what a query
    /// of one path holds, once the path is chosen.
    fn untyped(self) -> FieldReference<W, T, C, P> {
        FieldReference {
            name: self.name,
            scope: self.scope,
            identity: self.identity,
            contexts: self.contexts,
            json: self.json,
            place: self.place,
            target: PhantomData,
        }
    }

    fn json<Op>(self, body: Body) -> JsonFieldQuery<T, Op, C::Start> {
        let options = self.json;
        JsonFieldQuery(self.held_query(JsonInput { options, body }, drop))
    }
}

/// A query of the value at a path named as text, from
/// [`FieldReference::at_text_path`]: one of the methods below makes it a
/// query.
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
        self.range(held(low), held(high))
    }

    fn range(self, low: Held, high: Held) -> JsonFieldQuery<T, AtPath<Between>, C::Start> {
        self.reference.json(Body::Between(self.path, low, high))
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
        self.ordering_of(compare, held(value))
    }

    fn ordering_of<Op>(self, compare: Compare, value: Held) -> JsonFieldQuery<T, Op, C::Start> {
        self.reference
            .json(Body::Ordering(compare, self.path, value))
    }
}

/// One path a document field declares, holding values of type `V`: what a
/// method under [`FieldReference::at`] returns. `O` is [`OrderedPath`] for a
/// path under `ordered = {..}` and [`EqualityPath`] for one under
/// `paths = {..}`. One of the methods below makes it a query. Each takes
/// the path's type ([`PathValue`]), and derives the operand
/// [`at_text_path`](FieldReference::at_text_path) derives for the same path
/// and value. The orderings are refused at compile time on an unordered
/// path.
pub struct DeclaredPath<W, T, C, P, V, O = OrderedPath> {
    reference: FieldReference<W, T, C, P>,
    path: &'static str,
    value: PhantomData<fn() -> (V, O)>,
}

impl<W, T, C, P, V, O> DeclaredPath<W, T, C, P, V, O> {
    /// The path `path` of the field `reference`, as the derive declared it.
    /// For generated code: the derive checked the path when it compiled the
    /// record.
    #[doc(hidden)]
    pub fn new<D>(reference: FieldReference<W, T, C, P, D>, path: &'static str) -> Self
    where
        W: Place,
        T: JsonQueries,
        C: ScopeInput,
    {
        Self {
            reference: reference.untyped(),
            path,
            value: PhantomData,
        }
    }
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P, V: JsonScalarType, O>
    DeclaredPath<W, T, C, P, V, O>
{
    /// The same query, with the path as text: one code path for both.
    fn text(self) -> ValueAt<W, T, C, P> {
        ValueAt {
            reference: self.reference,
            path: path_text(self.path),
        }
    }

    /// Rows with `value` at the path: containment of the document that
    /// holds it there, so exact. At a path with a wildcard, rows where any
    /// element holds it.
    pub fn eq(self, value: impl PathValue<V>) -> JsonFieldQuery<T, AtPath<Eq>, C::Start> {
        self.text().eq(value)
    }

    /// Rows with a JSON `null` at the path. A row with no node at the path
    /// does not match: that is `SQL NULL`, not a JSON `null`.
    pub fn is_null(self) -> JsonFieldQuery<T, AtPath<Eq>, C::Start> {
        self.text().is_null()
    }

    /// Rows where the value at the path is below `value`. An ordered path
    /// only.
    pub fn lt(self, value: impl PathValue<V>) -> JsonFieldQuery<T, AtPath<Lt>, C::Start>
    where
        O: OrderedPathKind,
    {
        self.text().ordering_of(Compare::Lt, held(value))
    }

    /// Rows where the value at the path is at or below `value`. An ordered
    /// path only.
    pub fn lte(self, value: impl PathValue<V>) -> JsonFieldQuery<T, AtPath<Lte>, C::Start>
    where
        O: OrderedPathKind,
    {
        self.text().ordering_of(Compare::Lte, held(value))
    }

    /// Rows where the value at the path is above `value`. An ordered path
    /// only.
    pub fn gt(self, value: impl PathValue<V>) -> JsonFieldQuery<T, AtPath<Gt>, C::Start>
    where
        O: OrderedPathKind,
    {
        self.text().ordering_of(Compare::Gt, held(value))
    }

    /// Rows where the value at the path is at or above `value`. An ordered
    /// path only.
    pub fn gte(self, value: impl PathValue<V>) -> JsonFieldQuery<T, AtPath<Gte>, C::Start>
    where
        O: OrderedPathKind,
    {
        self.text().ordering_of(Compare::Gte, held(value))
    }

    /// Rows where the value at the path is between `low` and `high`, both
    /// included. The query returns the two operands, low then high. An
    /// ordered path only.
    pub fn between(
        self,
        low: impl PathValue<V>,
        high: impl PathValue<V>,
    ) -> JsonFieldQuery<T, AtPath<Between>, C::Start>
    where
        O: OrderedPathKind,
    {
        self.text().range(held(low), held(high))
    }

    /// The path's selector, which `col -> $1` and an `ORDER BY` over
    /// `eql_v4.ord_term(col -> $1)` take.
    pub fn selector(self) -> JsonFieldQuery<T, Selector, C::Start> {
        self.text().selector()
    }
}

/// An element-scoped predicate on an array named as text, before its first
/// condition, from [`FieldReference::elements_text_path`]. Each method adds
/// a condition and makes it a query, to which more conditions can be added.
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
        impl<W: Place, T: JsonQueries, C: ScopeInput, P, A, V: JsonPathType>
            ElementMember<ArrayElements<W, T, C, P, A>, V>
        {
            $(
                $(#[$doc])*
                pub fn $method(
                    self,
                    value: impl PathValue<V>,
                ) -> JsonFieldQuery<T, ElementMatch<A>, C::Start> {
                    self.query.first(self.member, Condition::One(Compare::$compare, held(value)))
                }
            )+
        }
        impl<T, A, S, V: JsonPathType> ElementMember<JsonFieldQuery<T, ElementMatch<A>, S>, V> {
            $(
                $(#[$doc])*
                pub fn $method(
                    self,
                    value: impl PathValue<V>,
                ) -> JsonFieldQuery<T, ElementMatch<A>, S> {
                    self.query.condition(self.member, Condition::One(Compare::$compare, held(value)))
                }
            )+
        }
    };
}
element_conditions! {
    /// The member equals `value`, as the ordering terms compare: text
    /// case- and accent-folded, numbers as 64-bit floats. Exact equality
    /// of any element is a path's `eq` ([`DeclaredPath::eq`], [`ValueAt::eq`]).
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

    fn first<A>(
        self,
        member: &str,
        condition: Condition,
    ) -> JsonFieldQuery<T, ElementMatch<A>, C::Start> {
        self.reference.json(Body::Elements {
            path: self.path,
            bound: None,
            members: vec![(path_text(member), condition)],
        })
    }
}

/// An element-scoped predicate on an array a document field declares, `A`,
/// before its first condition: the receiver of the array's member methods,
/// from a method under [`FieldReference::elements`]. A condition on a member
/// makes it a query. It has no `encrypt`, since a predicate with no
/// condition is true of no element.
pub struct ArrayElements<W, T, C, P, A> {
    reference: FieldReference<W, T, C, P>,
    path: &'static str,
    array: PhantomData<fn() -> A>,
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P, A> ArrayElements<W, T, C, P, A> {
    /// The array at `path`, a path with a wildcard, of the field
    /// `reference`, as the derive declared it. For generated code: the
    /// derive checked the path when it compiled the record.
    #[doc(hidden)]
    pub fn new<D>(reference: FieldReference<W, T, C, P, D>, path: &'static str) -> Self {
        Self {
            reference: reference.untyped(),
            path,
            array: PhantomData,
        }
    }

    /// The query of the first condition, as the text form makes it.
    fn first(
        self,
        member: &str,
        condition: Condition,
    ) -> JsonFieldQuery<T, ElementMatch<A>, C::Start> {
        Elements {
            reference: self.reference,
            path: path_text(self.path),
        }
        .first(member, condition)
    }
}

/// One ordered member of the elements of a declared array, holding values of
/// type `V`: what a member method of the array returns. `Q` is the
/// predicate the member's condition goes into: the array before its first
/// condition ([`ArrayElements`]), or the query its earlier conditions made.
/// One of the methods below adds the condition, and each takes the
/// member's type ([`PathValue`]).
pub struct ElementMember<Q, V> {
    query: Q,
    member: &'static str,
    value: PhantomData<fn() -> V>,
}

impl<Q, V> ElementMember<Q, V> {
    /// The member `member`, a path relative to an element (`place`,
    /// `address.city`), adding to `query`. For generated code: the derive
    /// checked the member when it compiled the record.
    #[doc(hidden)]
    pub fn new(query: Q, member: &'static str) -> Self {
        Self {
            query,
            member,
            value: PhantomData,
        }
    }
}

impl<W: Place, T: JsonQueries, C: ScopeInput, P, A, V: JsonPathType>
    ElementMember<ArrayElements<W, T, C, P, A>, V>
{
    /// The member lies between `low` and `high`, both included.
    pub fn between(
        self,
        low: impl PathValue<V>,
        high: impl PathValue<V>,
    ) -> JsonFieldQuery<T, ElementMatch<A>, C::Start> {
        self.query
            .first(self.member, Condition::Between(held(low), held(high)))
    }
}

impl<T, A, S, V: JsonPathType> ElementMember<JsonFieldQuery<T, ElementMatch<A>, S>, V> {
    /// The member lies between `low` and `high`, both included.
    pub fn between(
        self,
        low: impl PathValue<V>,
        high: impl PathValue<V>,
    ) -> JsonFieldQuery<T, ElementMatch<A>, S> {
        self.query
            .condition(self.member, Condition::Between(held(low), held(high)))
    }
}

impl<T, S> JsonFieldQuery<T, ElementMatch, S> {
    /// The member lies between `low` and `high`, both included.
    pub fn between<V: JsonOrdered>(self, member: &str, low: V, high: V) -> Self {
        self.condition(member, Condition::Between(held(low), held(high)))
    }
}

impl<T, A: ElementArray, S> JsonFieldQuery<T, ElementMatch<A>, S> {
    /// The members of the array the predicate is on, to add another
    /// condition: `place().eq("home").and().at().gt(15)`. Every condition
    /// holds of one element together.
    pub fn and(self) -> A::Members<Self> {
        A::members(self)
    }
}

impl<T, A, S> JsonFieldQuery<T, ElementMatch<A>, S> {
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
    /// One of the predicate's variables, which the predicate names as
    /// `$name`: `predicate("$.age >= $min").var("min", 30)`. Together they
    /// are the `vars` object `jsonb_path_match` takes. `value` is a scalar,
    /// as a path's `eq` takes. A NaN or an infinity is refused when the
    /// query is encrypted ([`TermError::JsonNumberNotFinite`]), and so is a
    /// name given twice (`Error::Input`, with
    /// [`Reason::JsonDuplicateKey`](crate::refusal::Reason::JsonDuplicateKey)),
    /// each before any key is requested.
    pub fn var(self, name: &str, value: impl JsonScalar) -> Self {
        self.variable(name, held(value))
    }

    /// A predicate variable that is a JSON `null`, which the predicate
    /// names as `$name`.
    pub fn var_null(self, name: &str) -> Self {
        self.variable(name, Held::Value(Parsed::of(Value::Null)))
    }

    fn variable(mut self, name: &str, value: Held) -> Self {
        if let Some(JsonInput {
            body: Body::Predicate { vars, .. },
            ..
        }) = self.0.value.as_mut()
        {
            vars.push((path_text(name), value));
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
            Err(error) => return Pending::failed(keyset, error.into_crate()),
        };
        let under = Under::new(&self.0.label, scopes);
        match inputs::derive(keyset, &under, &options, checked) {
            Ok(pending) => pending,
            Err(error) => Pending::failed(keyset, error.into_crate()),
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

impl<T: JsonQueries> JsonFieldQuery<T, Children, Ready> {
    /// Derives the node's token, as the field's type stores it, with the
    /// key that holds it: [`encrypt`](Self::encrypt)'s token, and the key
    /// that opens each entry `json_tree_children` returns for it
    /// ([`JsonSubtreeKey::open_child`]). Both come from one derivation, so
    /// the key is the key of the token sent. Bind the token, and keep the
    /// key to open what the query returns.
    ///
    /// The query is checked under the field's options before any key is
    /// requested, and its path is wiped when it is derived, refused or
    /// dropped. The operand is derived locally: it requests no key.
    ///
    /// [`JsonSubtreeKey::open_child`]: crate::json::JsonSubtreeKey::open_child
    pub fn encrypt_keyed<'a, K: 'static>(
        mut self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, (T::Token, JsonSubtreeKey), K> {
        self.derive_json(keyset).try_map(|derived| match derived {
            Derived::Node(key) => Ok((T::token(key.clone())?, key)),
            _ => Err(mismatched()),
        })
    }
}

impl<T: JsonQueries, A> JsonFieldQuery<T, ElementMatch<A>, Ready> {
    /// Derives the element-scoped predicate.
    ///
    /// The query is checked under the field's options before any key is
    /// requested, and its values are wiped when it is derived, refused or
    /// dropped. The operand is derived locally: it requests no key.
    pub fn encrypt<'a, K: 'static>(
        mut self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, T::ElementsQuery, K> {
        self.derive_json(keyset).try_map(|derived| match derived {
            Derived::Elements(query) => T::elements_query(query),
            _ => Err(mismatched()),
        })
    }
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
