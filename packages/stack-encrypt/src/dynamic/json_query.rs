//! The JSON operators of a document field, for a binding: queries named by
//! operator, and reads opened against the request that prepared them.
//!
//! A field that names a target storing a document (`JsonSearch`) runs
//! under the JSON index's options its plan resolved
//! ([`TargetOptions::Json`](super::TargetOptions::Json)). Each operator
//! takes an object of named inputs and gives a tagged operand
//! ([`Operand`]):
//!
//! | operator | input | operand |
//! |---|---|---|
//! | `contains`, `contained_by` | `{"json"}`: a JSON document | EQL: the document's selector set (`eql_v4.query_json`) |
//! | `eq_at` | `{"path", "json"}`: a scalar at a path | EQL: the selector set of the document holding the scalar there |
//! | `lt_at`, `lte_at`, `gt_at`, `gte_at` | `{"path", "json"}`: a number or string at an ordered path | EQL: the path's selector and the leaf's ordering term (`eql_v4.query_json_leaf`) |
//! | `between_at` | `{"path", "low", "high"}` | EQL, two of them: the low bound's then the high's |
//! | `selector` | `{"path"}` | text: the selector `->` takes |
//! | `subtree` | `{"path", "wildcard_bound"?}` | text array: the tokens `json_tree_subtree` takes |
//! | `children`, `child_count` | `{"path"}`: a path with no wildcard | text: the node's token |
//! | `element_match` | `{"path", "wildcard_bound"?, "predicates"}`: an array's elements, by a path with a wildcard, and predicates on fields of an element at ordered paths | EQL: per predicate, the field's read tokens and its bounds (`eql_v4.query_json_elements`), compared as the orderings compare, so its `eq` is of folded values |
//! | `match` | `{"predicate", "vars"?, "wildcard_bound"?}`: a jsonpath predicate in the subset below, and its variables as one JSON object | EQL: the predicate as a boolean tree of the operands above (`eql_v4.query_json_predicate`), which `json_tree_match` and `@@` evaluate |
//!
//! Every JSON value in an input is UTF-8 JSON text, parsed by
//! [`parse_text`](crate::json::parse_text)'s rules. A path is JSONPath text
//! ([`JsonPath::parse`]). A position in a path (`[2]`) is refused for the
//! operators whose operand is a selector (`eq_at`, the orderings,
//! `selector`): a selector reads every position as the wildcard, so the
//! query would compare whichever element the database found first. A
//! positional read is a `subtree` read. Equality at a wildcard path matches
//! when any element matches. `->` at a wildcard path, and an ordering
//! written over it (`eql_v4.ord_term(col -> sel)`), see an unspecified
//! element of the row, since entries are stored in a random order; an
//! ordering over every element is written over all its matches
//! (`json_tree_path_query`). Two `eq_at` predicates on one row need not
//! hold of the same array element; one containment query of a document
//! holding both does.
//!
//! # Element predicates
//!
//! `element_match` asks whether some one element of an array satisfies
//! every predicate, which two `eq_at` or ordering operands cannot: the
//! jsonpath `exists($.contacts[*] ? (@.relationship == "Sibling" &&
//! @.calls > 5))`. Its input names the array's elements by a path with a
//! wildcard (`$.contacts[*]`), and each predicate a field of an element by
//! a `member` path relative to it (`relationship`, `address.postcode`,
//! `["first name"]`), an `op` and its value:
//!
//! ```json
//! {"path": "$.contacts[*]", "wildcard_bound": 16, "predicates": [
//!   {"member": "relationship", "op": "eq", "json": "\"Sibling\""},
//!   {"member": "calls", "op": "gt", "json": "5"},
//!   {"member": "age", "op": "between", "low": "18", "high": "40"}
//! ]}
//! ```
//!
//! `op` is `eq`, `lt`, `lte`, `gt` or `gte`, with `json`, or `between`,
//! with `low` and `high`, inclusive. Each member's full path, the path and
//! the member joined, must be one the field orders. The operand holds, per
//! predicate, the tokens of a `subtree` read of the full path at the bound,
//! and the bounds as the orderings derive them: `gt` the leaf operand
//! `gt_at` derives, `between` the two `between_at` derives as `gte` and
//! `lte`, and `eq` one leaf operand as both `gte` and `lte`. So equality
//! here is the ordering term's: text compares case- and accent-folded, and
//! numbers as float64, so integers past 2^53 can tie. Exact equality at a
//! path is `eq_at`, of any element.
//!
//! Refused before anything is derived, each by its reason: a path with no
//! wildcard ([`Reason::JsonPathNoWildcard`]), a `wildcard_bound` of `0`,
//! whose operand could never be true ([`Reason::JsonWildcardBoundZero`]),
//! an empty list of predicates ([`Reason::JsonNoPredicates`]), an `op`
//! that is none of the six ([`Reason::JsonUnknownPredicateOp`]), a
//! predicate whose keys do not fit its `op` ([`Reason::JsonInput`]), a
//! wildcard in a member ([`Reason::JsonPathWildcard`]); and by the index's
//! own refusals, a position in the path or a member
//! ([`TermError::JsonOrderingAtPosition`]), a member whose full path the
//! field does not order ([`TermError::JsonPathNotOrdered`]), a value that
//! is not a number or a string ([`TermError::JsonLeafNotOrdered`]), and a
//! member that is not a path ([`TermError::JsonPath`], at an offset into
//! the member's own text). The
//! database refuses a row whose array is longer than the bound, as a
//! subtree read of it opens to a refusal: each member's tokens end with
//! the probe, and `json_tree_element_match` raises when it names a node.
//!
//! # Compiled predicates
//!
//! `match` takes what plaintext `jsonb_path_match(col, $1, $2)` takes: a
//! jsonpath predicate and its variables, `vars` the JSON text of one object
//! (`{}` when absent). It compiles the predicate into one operand, a tree
//! of `and`, `or` and `not` over the operands the operators above derive,
//! each leaf derived by its operator's own code:
//!
//! ```json
//! {"predicate": "$.age >= $min && exists($.contacts[*] ? (@.relationship == $r && @.calls > 5))",
//!  "vars": "{\"min\": 18, \"r\": \"Sibling\"}", "wildcard_bound": 16}
//! ```
//!
//! The grammar is the subset of SQL/JSON path predicates the terms answer,
//! as PostgreSQL reads it: a path is `$` and steps `.key`, `."quoted key"`
//! (JSON's escapes) and `[*]`; a value is a variable (`$v`, `$"v"`) or a
//! JSON literal (a string, a number, `true`, `false`, `null`); predicates
//! are comparisons of a path with a value (`==`, `!=` or `<>`, `<`, `<=`,
//! `>`, `>=`, either side first), `exists(path)` and `exists(path ? (…))`
//! with a filter of comparisons on `@` and `@.member` joined by `&&`, and
//! `&&`, `||`, `!(…)` and parentheses over them. Each maps onto operands
//! this way:
//!
//! | jsonpath | operand |
//! |---|---|
//! | `P == v`, `P == null` | `eq_at`'s containment needle |
//! | `P != v`, `P != null` | `selector` and not that needle: a node there that is not the value |
//! | `P < v` … `P >= v` | `selector` and the ordering's leaf: a node there whose leaf compares; under an odd number of `!`, also not the `null` needle |
//! | `P < v` … `P >= v`, `P` with a wildcard | `element_match` on the array through `P`'s last wildcard, the rest of `P` its member |
//! | `exists(P)` | `selector` |
//! | `exists(P ? (@.m == v))`, `exists(P ? (@ == v))` | `eq_at` at `P.m` or `P` |
//! | `exists(P ? (@.m op v && …))` | `element_match` on `P`'s elements, one predicate per condition |
//!
//! So the tree is true of exactly the rows `jsonb_path_match` is true of
//! over the plaintext, and answers as it does, true, false or NULL
//! (unknown) as SQL's three-valued logic combines them. An absent path is
//! false under every comparison, `!=` is true of a `null`, and an ordering
//! is unknown of a node with no ordering term (a boolean, a container), as
//! jsonpath's comparison of two kinds is. A JSON `null` is false under an
//! ordering in jsonpath. The tree says so only where it changes the rows,
//! under an odd number of `!`, by sending the `null` needle, which tells
//! the database which rows hold `null` at the path. Elsewhere it sends no
//! needle and an ordering of a `null` is NULL, which `and` and `or` cannot
//! turn into true, so the rows are the same. The tree's answer
//! and jsonpath's part in four places, each a property of the stored
//! document or of the ordering terms rather than of the predicate:
//!
//! - A path is read as written: lax mode unwraps an array the path names
//!   no `[*]` for (`$.tags == "a"` over `{"tags": ["a"]}` is true), and
//!   the tree does not. Write `[*]`.
//! - Lax mode also wraps a value that is not an array where the path names
//!   `[*]`: `$.tags[*] == "a"` over `{"tags": "a"}`, `exists($.tags[*])`
//!   over a scalar `tags` and `exists($.items[*] ? (@.sku == "x"))` over
//!   `{"items": {"sku": "x"}}` are all true to jsonpath. The tree finds
//!   only array elements at `[*]`, since `$.tags[*]` and `$.tags` have
//!   different selectors, so each is false here. Keep an array an array.
//! - A comparison of a string with a number, or of a boolean with a
//!   string or a number, is unknown to jsonpath. The terms do not record
//!   a value's kind, so the tree answers it false under `==` (and in a
//!   filter, as jsonpath's filter does), true under `!=`, and by the
//!   ordering terms under an ordering. Keep one kind of value at a path.
//! - An ordering compares the ordering terms, as the orderings do: text
//!   case- and accent-folded, numbers as float64. So does every condition
//!   of a filter of more than one, `element_match`'s, whose equality is
//!   therefore of folded values; `==` elsewhere is exact.
//!
//! An ordering at a path the field does not order is refused, as the
//! orderings refuse it.
//!
//! Refused, each at the byte of the caller's text where the construct
//! starts and naming the construct by the grammar's words and never the
//! text ([`Error::Predicate`]): text the grammar does not read
//! ([`Reason::JsonPredicateSyntax`]); arithmetic, `like_regex`, `starts
//! with`, `is unknown`, a method (`.size()`), a mode word (`strict`,
//! `lax`), `.*`, `.**`, a slice, `last`, a comparison of two paths or two
//! values, a filter outside `exists`, and `||`, `!`, `!=` or `exists`
//! inside a filter ([`Reason::JsonPredicateUnsupported`]); a variable
//! `vars` does not hold ([`Reason::JsonPredicateUnknownVariable`]); a
//! value of a type its comparison cannot take, an object or array
//! anywhere, and under an ordering or in a filter of more than one
//! condition anything but a number or a string
//! ([`Reason::JsonPredicateValueType`]); `!=` at a path with a wildcard
//! ([`Reason::JsonPredicateNotEqualAtWildcard`]); nesting past 32 levels or
//! a path deeper than a document ([`Reason::JsonPredicateTooDeep`]); a
//! position (`[2]`, [`Reason::JsonPathPosition`]); a filter on a path with
//! no wildcard ([`Reason::JsonPathNoWildcard`]); and a wildcard in a
//! filter's member ([`Reason::JsonPathWildcard`]). The leaves' operators
//! refuse their own inputs as they would alone: an ordering at a path the
//! field does not order ([`TermError::JsonPathNotOrdered`]). A
//! `wildcard_bound` of `0` is [`Reason::JsonWildcardBoundZero`], and `vars`
//! that are not an object [`Reason::JsonInput`].
//!
//! The operand reveals what its leaves reveal when sent one by one, and
//! the boolean shape of the filter; an ordering under an odd number of `!`
//! sends the `null` needle too, one leaf more than the ordering alone
//! sends. `json_tree_match` evaluates the
//! tree inside a function, which engages no index, so a predicate written
//! out per operator is the fast path.
//!
//! # Reads
//!
//! [`json_open`] opens the rows a read returned, against the request that
//! prepared the read: the operator, the path and the bound. The engine
//! derives the selector or the read key again from that request, the
//! field's definition and the keyset, and checks every row against it with
//! the index's own checks: [`JsonSelector::open`],
//! [`JsonSubtreeKey::open`](crate::json::JsonSubtreeKey::open), and
//! [`JsonSubtreeKey::open_child`](crate::json::JsonSubtreeKey::open_child).
//! For a `children` read, each entry must be a child of the node at the
//! request's path. The rows never say which path they are for. Each group
//! of rows opens on its own, so entries of two documents are never one
//! walk.
//!
//! What opening proves is limited, as the index documents: a row of the
//! column other than the one asked for can answer, an element under one
//! array element can stand for the same field under another, and the
//! database can leave whole nodes out. Opening does not prove the result is
//! complete.

use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use serde_json::Value;
use vitaminc_aead::plaintext::visit_map;
use vitaminc_aead::Sink;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

use super::query::{Op, Operand};
use super::{Error, Reason, ValueFrame};
pub(super) use crate::json::inputs::Under;
use crate::json::inputs::{
    elements_base, json_reason, leaf, member_path, node_path, ordered_path, path, scalar,
    selector_path, wildcard_bound, Bounds, Compare, Derived, Input, Parsed, Predicate,
};
use crate::json::{
    parse_text, ChildLabel, JsonChildPlaintext, JsonNode, JsonOptions, JsonPath, JsonPlaintext,
    JsonSubtreeKey,
};
use crate::{DecryptFrom, Encrypt, KeysetCipher, Pending};

/// The SQL type a JSON operand binds as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Binds {
    /// The target's query domain (`eql_v4.query_json`).
    Query,
    /// The target's leaf operand domain (`eql_v4.query_json_leaf`).
    Leaf,
    /// `text`.
    Text,
    /// `text[]`.
    TextArray,
    /// The target's element predicate domain (`eql_v4.query_json_elements`).
    Elements,
    /// The target's compiled predicate domain (`eql_v4.query_json_predicate`).
    Predicate,
}

/// What a JSON operator's operand binds as, or `None` for an operator
/// that is not one: the one table that says which operators the JSON
/// index answers ([`Op::is_json`]). Exhaustive, so a new operator
/// must be placed.
pub(super) fn binds(op: Op) -> Option<Binds> {
    match op {
        Op::Contains | Op::ContainedBy | Op::EqAt => Some(Binds::Query),
        Op::LtAt | Op::LteAt | Op::GtAt | Op::GteAt | Op::BetweenAt => Some(Binds::Leaf),
        Op::Selector | Op::Children | Op::ChildCount => Some(Binds::Text),
        Op::Subtree => Some(Binds::TextArray),
        Op::ElementMatch => Some(Binds::Elements),
        Op::Match => Some(Binds::Predicate),
        Op::Eq | Op::Matches | Op::Lt | Op::Lte | Op::Gt | Op::Gte | Op::Between => None,
    }
}

/// The SQL type an operand of `binds` binds as for `target`: its query
/// or leaf domain, which a resolver may not name, or text.
pub(super) fn domain(target: &super::TargetDescriptor, binds: Binds) -> Option<String> {
    match binds {
        Binds::Query => target.query_sql_domain.clone(),
        Binds::Leaf => target.leaf_query_sql_domain.clone(),
        Binds::Text => Some("text".to_owned()),
        Binds::TextArray => Some("text[]".to_owned()),
        Binds::Elements => target.elements_query_sql_domain.clone(),
        Binds::Predicate => target.predicate_query_sql_domain.clone(),
    }
}

/// UTF-8 JSON text in an input: a text or bytes leaf, held in a buffer
/// wiped on drop. Also how `match` holds its predicate's text, whose
/// literals are values.
pub(super) struct JsonText(pub(super) Zeroizing<Vec<u8>>);

impl<'de> Deserialize<'de> for JsonText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = JsonText;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON text, as text or bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<JsonText, E> {
                Ok(JsonText(Zeroizing::new(v.as_bytes().to_vec())))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<JsonText, E> {
                Ok(JsonText(Zeroizing::new(v.to_vec())))
            }
        }
        d.deserialize_any(V)
    }
}

/// The text of a path, or of a member of one, in an operator's input. It
/// names keys, which are plaintext, so it is wiped on drop. It is copied
/// from the input at its own length and never grows.
pub(super) struct PathText(Zeroizing<String>);

impl std::ops::Deref for PathText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PathText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = PathText;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a path, as text")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<PathText, E> {
                Ok(PathText(Zeroizing::new(v.to_owned())))
            }
        }
        d.deserialize_str(V)
    }
}

impl JsonText {
    pub(super) fn parse(&self) -> Result<Parsed, Error> {
        parse_text(&self.0)
            .map(Parsed::of)
            .map_err(|error| Error::Source {
                field: None,
                reason: json_reason(error),
            })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentInput {
    json: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AtInput {
    path: PathText,
    json: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BetweenInput {
    path: PathText,
    low: JsonText,
    high: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathInput {
    path: PathText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    path: PathText,
    #[serde(default)]
    wildcard_bound: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ElementsInput {
    path: PathText,
    #[serde(default)]
    wildcard_bound: Option<u32>,
    predicates: Vec<PredicateInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PredicateInput {
    member: PathText,
    op: String,
    #[serde(default)]
    json: Option<JsonText>,
    #[serde(default)]
    low: Option<JsonText>,
    #[serde(default)]
    high: Option<JsonText>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchInput {
    predicate: JsonText,
    #[serde(default)]
    vars: Option<JsonText>,
    #[serde(default)]
    wildcard_bound: Option<u32>,
}

fn read_frame<T: for<'de> Deserialize<'de>>(input: &ValueFrame) -> Result<T, Error> {
    vitaminc_aead_frame::serde::from_slice(input.risky_ref()).map_err(|_| Error::Source {
        field: None,
        reason: Reason::JsonInput,
    })
}

/// Read and check an operator's input against the field's options: the
/// frame read into the input the operator takes ([`Input`]), checked with
/// the rules a field reference's typed JSON queries apply, and in the order a
/// binding has always met them.
fn read_input(op: Op, options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    match op {
        Op::Contains | Op::ContainedBy => Ok(Input::Document(
            read_frame::<DocumentInput>(input)?.json.parse()?,
        )),
        Op::EqAt => read_eq_at(input),
        Op::LtAt => read_ordering(options, Compare::Lt, input),
        Op::LteAt => read_ordering(options, Compare::Lte, input),
        Op::GtAt => read_ordering(options, Compare::Gt, input),
        Op::GteAt => read_ordering(options, Compare::Gte, input),
        Op::BetweenAt => read_between(options, input),
        Op::Selector => Ok(Input::Selector(selector_path(
            &read_frame::<PathInput>(input)?.path,
        )?)),
        Op::Children | Op::ChildCount => Ok(Input::Node(node_path(
            &read_frame::<PathInput>(input)?.path,
        )?)),
        Op::Subtree => {
            let read: ReadInput = read_frame(input)?;
            Ok(Input::Read(
                path(&read.path)?,
                read.wildcard_bound.unwrap_or(JsonSubtreeKey::DEFAULT_BOUND),
            ))
        }
        Op::ElementMatch => read_elements(options, input),
        Op::Match => read_match(options, input),
        _ => Err(Error::Internal),
    }
}

/// `match`'s input: a jsonpath predicate, its variables as one JSON object
/// (the `vars` jsonb `jsonb_path_match` takes, `{}` when absent) and the
/// bound its element-scoped leaves are read to. The predicate is compiled
/// here, so every refusal it can meet is met before anything is derived.
fn read_match(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let input: MatchInput = read_frame(input)?;
    let bound = wildcard_bound(input.wildcard_bound)?;
    let vars = match &input.vars {
        Some(vars) => vars.parse()?,
        None => Parsed::of(Value::Object(serde_json::Map::new())),
    };
    if !vars.0.is_object() {
        return Err(Error::bad_source(Reason::JsonInput));
    }
    let text = std::str::from_utf8(&input.predicate.0)
        .map_err(|_| Error::bad_source(Reason::JsonInput))?;
    Input::predicate(options, text, &vars.0, Some(bound))
}

/// `element_match`'s input: an array's elements, by a path with a wildcard
/// and no position, and one or more predicates on their fields.
fn read_elements(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let elements: ElementsInput = read_frame(input)?;
    let base = elements_base(&elements.path)?;
    let bound = wildcard_bound(elements.wildcard_bound)?;
    if elements.predicates.is_empty() {
        return Err(Error::bad_source(Reason::JsonNoPredicates));
    }
    let predicates = elements
        .predicates
        .iter()
        .map(|predicate| read_predicate(options, &base, predicate))
        .collect::<Result<Vec<_>, _>>()?;
    Input::elements(Some(bound), predicates)
}

/// One predicate of `element_match`: its member's full path below `base`,
/// which the field must order, and the bounds its `op` takes.
fn read_predicate(
    options: &JsonOptions,
    base: &JsonPath,
    predicate: &PredicateInput,
) -> Result<Predicate, Error> {
    let compare = match predicate.op.as_str() {
        "eq" => Some(Compare::Eq),
        "lt" => Some(Compare::Lt),
        "lte" => Some(Compare::Lte),
        "gt" => Some(Compare::Gt),
        "gte" => Some(Compare::Gte),
        "between" => None,
        _ => return Err(Error::bad_source(Reason::JsonUnknownPredicateOp)),
    };
    let path = member_path(options, base, &predicate.member)?;
    let value = |text: &JsonText| -> Result<Parsed, Error> {
        let value = text.parse()?;
        leaf(&value.0)?;
        Ok(value)
    };
    let bounds = match (compare, &predicate.json, &predicate.low, &predicate.high) {
        (Some(compare), Some(json), None, None) => Bounds::One(compare, value(json)?),
        (None, None, Some(low), Some(high)) => Bounds::Between(value(low)?, value(high)?),
        _ => return Err(Error::bad_source(Reason::JsonInput)),
    };
    Ok(Predicate { path, bounds })
}

/// `eq_at`'s input: a scalar at a path read through a selector.
fn read_eq_at(input: &ValueFrame) -> Result<Input, Error> {
    let at: AtInput = read_frame(input)?;
    let path = selector_path(&at.path)?;
    let value = at.json.parse()?;
    scalar(&value.0)?;
    Ok(Input::EqAt(path, value))
}

/// An ordering's input: a leaf the index orders at an ordered path.
fn read_ordering(
    options: &JsonOptions,
    compare: Compare,
    input: &ValueFrame,
) -> Result<Input, Error> {
    let at: AtInput = read_frame(input)?;
    let path = ordered_path(options, &at.path)?;
    let value = at.json.parse()?;
    leaf(&value.0)?;
    Ok(Input::Ordering(compare, path, value))
}

/// `between_at`'s input: two leaves the index orders at an ordered path.
fn read_between(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let between: BetweenInput = read_frame(input)?;
    let path = ordered_path(options, &between.path)?;
    let (low, high) = (between.low.parse()?, between.high.parse()?);
    leaf(&low.0)?;
    leaf(&high.0)?;
    Ok(Input::Between(path, low, high))
}

/// Check a JSON operator's input without a cipher: what [`derive`] refuses
/// from the input alone (its shape, its paths and values, a path deeper
/// than a document). The limits a subtree read's key hits as it is built,
/// a wildcard expanding too wide or a path too deep for its tokens
/// (`JsonWildcardTooWide`, `JsonTooWide`, `JsonTooDeep`), are [`derive`]'s,
/// after the keyset is resolved.
pub(super) fn check(op: Op, options: &JsonOptions, input: &ValueFrame) -> Result<(), Error> {
    read_input(op, options, input).map(drop)
}

pub(super) fn eql<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, crate::Error> {
    serde_json::to_vec(value).map_err(|error| crate::Error::Other(Box::new(error)))
}

/// Derive a JSON operator's operand for one input, under the field's query
/// context and options, as a binding binds it. Derived locally: the pending
/// carries no request.
pub(super) fn derive<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    op: Op,
    input: &ValueFrame,
) -> Result<Pending<'a, Operand, K>, Error> {
    Ok(
        crate::json::inputs::derive(keyset, under, options, read_input(op, options, input)?)?
            .try_map(operand),
    )
}

/// An operand as a binding binds it: an EQL value's JSON bytes, the two of
/// a range, or text.
fn operand(derived: Derived) -> Result<Operand, crate::Error> {
    Ok(match derived {
        Derived::Query(query) => Operand::One(eql(&query)?),
        Derived::Leaf(leaf) => Operand::One(eql(&leaf)?),
        Derived::Range(lo, hi) => Operand::Range {
            lo: eql(&lo)?,
            hi: eql(&hi)?,
        },
        Derived::Selector(selector) => Operand::Text(selector.to_string()),
        Derived::Node(key) => {
            // `json::inputs::derive` checked the key holds one token.
            Operand::Text(key.tokens().concat())
        }
        Derived::Read(key) => Operand::TextList(key.tokens()),
        Derived::Elements(elements) => Operand::One(eql(&elements)?),
        Derived::Predicate(predicate) => Operand::One(eql(&predicate)?),
    })
}

/// A read to open, as the request that prepared it names it: the
/// operator, the path and, for a subtree read, the wildcard bound. What a
/// binding keeps from preparing the read and hands back with its rows; the
/// engine derives the selector or the key again from it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    operation: String,
    path: PathText,
    #[serde(default)]
    wildcard_bound: Option<u32>,
}

/// The groups of rows a read returned: one list of entries per database
/// row, each entry the `public.eql_v4_json_entry` JSON the SQL
/// returned, as text or bytes.
#[derive(Deserialize)]
#[serde(transparent)]
struct Groups(Vec<Vec<JsonText>>);

/// A read as its request names it, checked.
enum Read {
    Selector(JsonPath),
    Subtree(JsonPath, u32),
    /// `children`: the parent's path. The path names one node.
    Child(JsonPath),
}

/// Reads and checks a read's request and its rows: everything [`open`]
/// refuses before it derives anything. A `selector` group and a `children`
/// group each contain one entry or none.
fn read_open(request: &ValueFrame, rows: &ValueFrame) -> Result<(Read, Vec<Vec<JsonNode>>), Error> {
    let request: ReadRequest = read_frame(request)?;
    let read = match Op::parse(&request.operation) {
        Some(Op::Selector) if request.wildcard_bound.is_none() => {
            Read::Selector(selector_path(&request.path)?)
        }
        Some(Op::Subtree) => Read::Subtree(
            path(&request.path)?,
            request
                .wildcard_bound
                .unwrap_or(JsonSubtreeKey::DEFAULT_BOUND),
        ),
        Some(Op::Children) if request.wildcard_bound.is_none() => {
            Read::Child(node_path(&request.path)?)
        }
        _ => return Err(Error::bad_source(Reason::JsonInput)),
    };
    let groups: Groups = read_frame(rows)?;
    let groups = groups
        .0
        .into_iter()
        .map(|group| {
            group
                .iter()
                .map(|row| serde_json::from_slice::<JsonNode>(&row.0))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::bad_source(Reason::JsonInput))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !matches!(read, Read::Subtree(..)) && groups.iter().any(|group| group.len() > 1) {
        return Err(Error::bad_source(Reason::JsonInput));
    }
    Ok((read, groups))
}

/// Check a read's request and rows without a cipher: what [`open`] refuses
/// from the request and rows alone. The limits the read's key hits as it
/// is built (`JsonWildcardTooWide`, `JsonTooWide`, `JsonTooDeep`) are
/// [`open`]'s, after the keyset is resolved.
pub(super) fn check_open(request: &ValueFrame, rows: &ValueFrame) -> Result<(), Error> {
    read_open(request, rows).map(drop)
}

/// What a read opens with: the selector or the subtree key, derived again
/// from the request. A `children` read opens with its parent's key
/// instead ([`open_children`]).
enum Opener {
    Selector(crate::json::JsonSelector),
    Subtree(JsonSubtreeKey),
}

/// Open the rows a read returned against the request that prepared it,
/// under the field's contexts and options and through `keyset`, the keyset
/// whose index key derived the read, and that keyset alone: a document
/// sealed under another is refused before any key is retrieved. The
/// selector or the read key derives under the field's query context, and
/// every entry opens under its stored context, so under the plan's
/// bindings too. [`json_open`](super::json_open) lists what each group
/// contains, and what each group opens to. One key request serves every
/// group.
///
/// # Errors
///
/// [`Error::Source`] with [`Reason::JsonInput`] for:
///
/// - a request or rows that do not parse;
/// - an operation that is not `selector`, `subtree`, or `children`;
/// - a `wildcard_bound` on a `selector` or a `children`;
/// - a `selector` or `children` group of more than one entry.
///
/// [`Reason::JsonPathWildcard`] for a `children` path with a wildcard.
/// [`Error::Cipher`] for the read's own refusals, such as a path that does
/// not parse, or a wildcard that expands too far.
///
/// The pending fails with [`crate::Error::JsonWrongEntry`] for an entry
/// the read did not ask for. It fails with
/// [`crate::Error::JsonWildcardTruncated`] for a wildcard read of an array
/// longer than the bound. It fails with [`crate::Error::JsonNotALeaf`] for
/// a `selector` or `children` entry that does not decrypt alone: a
/// container with members, or an altered entry.
pub(super) fn open<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    request: &ValueFrame,
    rows: &ValueFrame,
) -> Result<Pending<'a, ValueFrame, K>, Error> {
    let (read, groups) = read_open(request, rows)?;
    if keyset.loaded_state().is_some() {
        return open_read(keyset, under, options, read, groups);
    }
    // A read opens its rows with a key derived under the keyset's index
    // key, and the rows' key requests are built from it. With a default
    // keyset that is not loaded yet, there is nothing to build from. So
    // the pending is built when it settles and has loaded the keyset. A
    // refusal of the read is then the pending's error.
    let (label, parts) = under.owned();
    let options = options.clone();
    Ok(Pending::after_load(keyset, move |keyset| {
        match open_read(keyset, &Under::new(&label, parts), &options, read, groups) {
            Ok(pending) => pending,
            Err(error) => Pending::failed(keyset, pending_error(error)),
        }
    }))
}

/// An error raised while a pending is built or fulfilled, as the pending's
/// own error: the engine's error itself, or the input error inside one.
fn pending_error(error: Error) -> crate::Error {
    match error {
        Error::Cipher(error) => error,
        other => crate::Error::Other(Box::new(other)),
    }
}

/// [`open`], for a read already read and checked, through a keyset that is
/// loaded.
fn open_read<'a, K: 'static>(
    keyset: &KeysetCipher<'a, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    read: Read,
    groups: Vec<Vec<JsonNode>>,
) -> Result<Pending<'a, ValueFrame, K>, Error> {
    let opener = match read {
        Read::Selector(path) => Opener::Selector(keyset.json_selector_now(&path, under.query()?)?),
        Read::Subtree(path, bound) => {
            Opener::Subtree(keyset.json_subtree_key_now(&path, options, bound, under.query()?)?)
        }
        Read::Child(path) => return open_children(keyset, under, options, &path, groups),
    };
    let context = || under.stored();
    // Opened through the client, confined to the deriving keyset, as a
    // record's leaves are through a keyset reference: the read's key is that
    // keyset's, so a document sealed under another cannot answer it.
    let opener_cipher = keyset.cipher();
    let confine = keyset.selector();
    let confined = |pending: Pending<'a, Vec<JsonPlaintext>, K>| pending.confined_to(&confine);
    let mut pendings: Vec<Pending<'a, Vec<JsonPlaintext>, K>> = Vec::with_capacity(groups.len());
    for nodes in groups {
        pendings.push(match &opener {
            Opener::Selector(selector) => match <[JsonNode; 1]>::try_from(nodes) {
                Ok([node]) => confined(
                    JsonPlaintext::decrypt_from_with_context(
                        selector.open(node),
                        opener_cipher,
                        context(),
                    )
                    .map(|value| vec![value]),
                ),
                // `read_open` allows a selector group one entry or none.
                Err(_) => Pending::ready(keyset, Ok(Vec::new())),
            },
            Opener::Subtree(key) => confined(Vec::<JsonPlaintext>::decrypt_from_with_context(
                key.open(nodes),
                opener_cipher,
                context(),
            )),
        });
    }
    Ok(Pending::all(keyset, pendings).try_map(opened_frame))
}

/// [`open_read`] for `children`. Each group's one entry opens against the
/// key of the parent at `path`. It opens to the child's key or index and
/// its value.
fn open_children<'a, K: 'static>(
    keyset: &KeysetCipher<'a, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    path: &JsonPath,
    groups: Vec<Vec<JsonNode>>,
) -> Result<Pending<'a, ValueFrame, K>, Error> {
    // The path has no wildcard, so the key holds one token, the parent's.
    // The bound is never used.
    let parent = keyset.json_subtree_key_now(
        path,
        options,
        JsonSubtreeKey::DEFAULT_BOUND,
        under.query()?,
    )?;
    let opener_cipher = keyset.cipher();
    let confine = keyset.selector();
    let mut pendings: Vec<Pending<'a, Vec<JsonChildPlaintext>, K>> =
        Vec::with_capacity(groups.len());
    for nodes in groups {
        pendings.push(match <[JsonNode; 1]>::try_from(nodes) {
            Ok([node]) => JsonChildPlaintext::decrypt_from_with_context(
                parent.open_child(node),
                opener_cipher,
                under.stored(),
            )
            .map(|child| vec![child])
            .confined_to(&confine),
            // `read_open` allows a `children` group one entry or none.
            Err(_) => Pending::ready(keyset, Ok(Vec::new())),
        });
    }
    Ok(Pending::all(keyset, pendings).try_map(children_frame))
}

/// The opened children as a frame, with one list per group. Each list
/// contains one map per child, either `{"key", "json"}` or
/// `{"index", "json"}`. Each child is
/// wiped when it is dropped here, once its text is written. Each text is
/// wiped once the frame holds it.
fn children_frame(groups: Vec<Vec<JsonChildPlaintext>>) -> Result<ValueFrame, crate::Error> {
    let opened: Result<Vec<Vec<OpenedChild<'_>>>, crate::Error> = groups
        .iter()
        .map(|group| group.iter().map(OpenedChild::of).collect())
        .collect();
    let frame = ValueFrame::of(&opened?).map_err(|error| crate::Error::Other(Box::new(error)));
    drop(groups);
    frame
}

/// One opened child as the frame carries it: its key or index, and its
/// value's JSON text. The text is wiped when it is dropped.
struct OpenedChild<'c> {
    child: &'c JsonChildPlaintext,
    json: Protected<Vec<u8>>,
}

impl<'c> OpenedChild<'c> {
    fn of(child: &'c JsonChildPlaintext) -> Result<Self, crate::Error> {
        let json = crate::json::to_text(child.value())
            .map(Protected::new)
            .map_err(|error| crate::Error::Other(Box::new(error)))?;
        Ok(Self { child, json })
    }
}

/// One entry of an [`OpenedChild`]'s map.
enum ChildField<'c> {
    Key(&'c str),
    Index(u64),
    Json(&'c Protected<Vec<u8>>),
}

impl Encrypt for ChildField<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            ChildField::Key(key) => key.visit(sink),
            ChildField::Index(index) => index.visit(sink),
            ChildField::Json(json) => json.visit(sink),
        }
    }
}

/// `{"key": text, "json": bytes}` for a member, `{"index": u64, "json":
/// bytes}` for an element.
impl Encrypt for &OpenedChild<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let label = match self.child.label() {
            ChildLabel::Key(key) => ("key", ChildField::Key(key.risky_ref())),
            ChildLabel::Index(index) => ("index", ChildField::Index(*index.risky_ref())),
        };
        visit_map(
            sink,
            Some(2),
            [label, ("json", ChildField::Json(&self.json))],
        )
    }
}

/// The opened groups as a frame: a list per group of each value's JSON
/// text, as bytes. Each value is wiped when it is dropped, here, once its
/// text is written, and each text once the frame holds it.
fn opened_frame(groups: Vec<Vec<JsonPlaintext>>) -> Result<ValueFrame, crate::Error> {
    let texts: Result<Vec<Vec<Protected<Vec<u8>>>>, crate::Error> = groups
        .iter()
        .map(|group| {
            group
                .iter()
                .map(|value| {
                    crate::json::to_text(value.value())
                        .map(Protected::new)
                        .map_err(|error| crate::Error::Other(Box::new(error)))
                })
                .collect()
        })
        .collect();
    drop(groups);
    ValueFrame::of(&texts?).map_err(|error| crate::Error::Other(Box::new(error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{Error as ValueError, StrDeserializer, U8Deserializer};

    #[test]
    fn a_path_is_read_from_text() {
        let path = PathText::deserialize(StrDeserializer::<ValueError>::new("$.a"))
            .unwrap_or_else(|error| panic!("text is a path: {error}"));
        assert_eq!(&*path, "$.a");
    }

    #[test]
    fn a_path_that_is_not_text_is_refused_naming_what_was_expected() {
        let Err(error) = PathText::deserialize(U8Deserializer::<ValueError>::new(7)) else {
            panic!("a number is not a path");
        };
        assert!(
            error.to_string().contains("a path, as text"),
            "the refusal names what a path is: {error}"
        );
    }
}
