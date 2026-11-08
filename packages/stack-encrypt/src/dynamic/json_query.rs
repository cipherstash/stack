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
//! the index's own checks ([`JsonSelector::open`],
//! [`JsonSubtreeKey::open`](crate::json::JsonSubtreeKey::open)). The rows
//! never say which path they are for. Each group of rows is one database
//! row's, and opens on its own: entries of two documents are never one walk.
//!
//! What opening proves is limited, as the index documents: a row of the
//! column other than the one asked for can answer, an element under one
//! array element can stand for the same field under another, and the
//! database can leave whole nodes out. Opening does not prove the result is
//! complete.

use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use serde_json::Value;
use vitaminc_protected::Protected;
use zeroize::Zeroizing;

use super::query::{OpSpec, Operand};
use super::{Error, Reason, ValueFrame};
use crate::json::{
    parse_text, wipe_value, JsonExtracted, JsonLeafQuery, JsonNode, JsonOptions, JsonPath,
    JsonQuery, JsonSubtree, JsonSubtreeKey,
};
use crate::sem::TermError;
use crate::target::{AeadContext, DeclaredContext, Index, Json, Owned};
use crate::{KeysetCipher, Label, NonEmpty, Pending};

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
/// index answers ([`OpSpec::is_json`]). Exhaustive, so a new operator
/// must be placed.
pub(super) fn binds(op: OpSpec) -> Option<Binds> {
    match op {
        OpSpec::Contains | OpSpec::ContainedBy | OpSpec::EqAt => Some(Binds::Query),
        OpSpec::LtAt | OpSpec::LteAt | OpSpec::GtAt | OpSpec::GteAt | OpSpec::BetweenAt => {
            Some(Binds::Leaf)
        }
        OpSpec::Selector | OpSpec::Children | OpSpec::ChildCount => Some(Binds::Text),
        OpSpec::Subtree => Some(Binds::TextArray),
        OpSpec::ElementMatch => Some(Binds::Elements),
        OpSpec::Match => Some(Binds::Predicate),
        OpSpec::Eq
        | OpSpec::Matches
        | OpSpec::Lt
        | OpSpec::Lte
        | OpSpec::Gt
        | OpSpec::Gte
        | OpSpec::Between => None,
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

/// A document parsed from an input, wiped when it drops.
#[derive(PartialEq)]
pub(super) struct Parsed(pub(super) Value);

impl Drop for Parsed {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

impl JsonText {
    pub(super) fn parse(&self) -> Result<Parsed, Error> {
        parse_text(&self.0)
            .map(Parsed)
            .map_err(|error| Error::Source {
                field: None,
                reason: json_reason(error),
            })
    }
}

/// The reason a JSON text refusal is reported with.
pub(super) fn json_reason(error: crate::json::JsonTextError) -> Reason {
    use crate::json::JsonTextError as E;
    match error {
        E::Syntax { .. } => Reason::JsonSyntax,
        E::DuplicateKey { .. } => Reason::JsonDuplicateKey,
        E::IntegerRange => Reason::JsonIntegerRange,
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
    path: String,
    json: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BetweenInput {
    path: String,
    low: JsonText,
    high: JsonText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathInput {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    path: String,
    #[serde(default)]
    wildcard_bound: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ElementsInput {
    path: String,
    #[serde(default)]
    wildcard_bound: Option<u32>,
    predicates: Vec<PredicateInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PredicateInput {
    member: String,
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

/// How a predicate of `element_match` compares its field with one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Compare {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
}

/// A predicate's bounds, as its input gives them.
#[derive(PartialEq)]
pub(super) enum Bounds {
    /// One value, compared by the predicate's `op`.
    One(Compare, Parsed),
    /// `between`: the low bound then the high, both inclusive.
    Between(Parsed, Parsed),
}

/// One predicate of `element_match`, checked: the full path of the
/// element's field, which the field orders, and its bounds.
#[derive(PartialEq)]
pub(super) struct Predicate {
    pub(super) path: JsonPath,
    pub(super) bounds: Bounds,
}

/// An operator's input, read from its frame and checked: everything
/// [`derive`] would refuse before it derives anything. `match`'s is its
/// predicate compiled to a tree of the other operators' inputs.
#[derive(PartialEq)]
pub(super) enum Input {
    Document(Parsed),
    At(JsonPath, Parsed),
    Between(JsonPath, Parsed, Parsed),
    Path(JsonPath),
    Read(JsonPath, u32),
    Elements(u32, Vec<Predicate>),
    Predicate(Box<super::json_predicate::Node>),
}

fn read_frame<T: for<'de> Deserialize<'de>>(input: &ValueFrame) -> Result<T, Error> {
    vitaminc_aead_frame::serde::from_slice(input.risky_ref()).map_err(|_| Error::Source {
        field: None,
        reason: Reason::JsonInput,
    })
}

/// A path from an input. A path with more steps than a document has
/// levels names no node, and the operators that build the document
/// holding a value there (`eq_at`, the orderings) would build one as deep
/// as the path, whose recursive drop could overflow the stack: it is
/// refused as too deep before anything is built, for every operator.
fn path(text: &str) -> Result<JsonPath, Error> {
    let path =
        JsonPath::parse(text).map_err(|error| Error::Cipher(TermError::JsonPath(error).into()))?;
    if path.segments().len() > crate::json::MAX_DEPTH {
        return Err(term(TermError::JsonTooDeep));
    }
    Ok(path)
}

/// A path whose operand is a selector, which reads a position as the
/// wildcard.
fn selector_path(text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    if path.names_a_position() {
        return Err(Error::bad_source(Reason::JsonPathPosition));
    }
    Ok(path)
}

/// A path that names one node: no wildcard.
fn node_path(text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    // `is_positional`: every array step names a position, so the path
    // has no wildcard and names at most one node.
    if path.is_positional() {
        Ok(path)
    } else {
        Err(Error::bad_source(Reason::JsonPathWildcard))
    }
}

fn term(error: TermError) -> Error {
    Error::Cipher(error.into())
}

/// Read and check an operator's input against the field's options.
fn read_input(op: OpSpec, options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    match op {
        OpSpec::Contains | OpSpec::ContainedBy => Ok(Input::Document(
            read_frame::<DocumentInput>(input)?.json.parse()?,
        )),
        OpSpec::EqAt => read_eq_at(input),
        OpSpec::LtAt | OpSpec::LteAt | OpSpec::GtAt | OpSpec::GteAt => {
            read_ordering(options, input)
        }
        OpSpec::BetweenAt => read_between(options, input),
        OpSpec::Selector => Ok(Input::Path(selector_path(
            &read_frame::<PathInput>(input)?.path,
        )?)),
        OpSpec::Children | OpSpec::ChildCount => Ok(Input::Path(node_path(
            &read_frame::<PathInput>(input)?.path,
        )?)),
        OpSpec::Subtree => {
            let read: ReadInput = read_frame(input)?;
            Ok(Input::Read(
                path(&read.path)?,
                read.wildcard_bound.unwrap_or(JsonSubtreeKey::DEFAULT_BOUND),
            ))
        }
        OpSpec::ElementMatch => read_elements(options, input),
        OpSpec::Match => read_match(options, input),
        _ => Err(Error::Internal),
    }
}

/// The wildcard bound an input names, or the default: never `0`, which
/// would send the probe alone, so an element predicate could never be true.
fn wildcard_bound(bound: Option<u32>) -> Result<u32, Error> {
    match bound.unwrap_or(JsonSubtreeKey::DEFAULT_BOUND) {
        0 => Err(Error::bad_source(Reason::JsonWildcardBoundZero)),
        bound => Ok(bound),
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
        None => Parsed(Value::Object(serde_json::Map::new())),
    };
    if !vars.0.is_object() {
        return Err(Error::bad_source(Reason::JsonInput));
    }
    let text = std::str::from_utf8(&input.predicate.0)
        .map_err(|_| Error::bad_source(Reason::JsonInput))?;
    Ok(Input::Predicate(Box::new(super::json_predicate::compile(
        text, &vars.0, options, bound,
    )?)))
}

/// `element_match`'s input: an array's elements, by a path with a wildcard
/// and no position, and one or more predicates on their fields.
fn read_elements(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let elements: ElementsInput = read_frame(input)?;
    let base = path(&elements.path)?;
    if base.is_positional() {
        return Err(Error::bad_source(Reason::JsonPathNoWildcard));
    }
    if base.names_a_position() {
        return Err(term(TermError::JsonOrderingAtPosition));
    }
    let bound = wildcard_bound(elements.wildcard_bound)?;
    if elements.predicates.is_empty() {
        return Err(Error::bad_source(Reason::JsonNoPredicates));
    }
    let predicates = elements
        .predicates
        .iter()
        .map(|predicate| read_predicate(options, &base, predicate))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Input::Elements(bound, predicates))
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

/// A member's full path: `base` and then the member's steps, read as a
/// path relative to an element (`name`, `address.city`, `["a b"]`). A
/// member names one field of each element, so it has no wildcard of its
/// own, and the full path is an ordering's: no position, and ordered. A
/// member that does not parse is refused at an offset into the member's
/// own text.
fn member_path(options: &JsonOptions, base: &JsonPath, member: &str) -> Result<JsonPath, Error> {
    let prefix = if member.starts_with('[') { "$" } else { "$." };
    let relative = JsonPath::parse(&format!("{prefix}{member}")).map_err(|error| {
        let error = crate::json::JsonPathError {
            at: error.at.saturating_sub(prefix.len()),
            ..error
        };
        Error::Cipher(TermError::JsonPath(error).into())
    })?;
    member_of(options, base, relative)
}

/// A member's full path, from the steps already parsed: the checks
/// [`member_path`] makes past parsing, which `match` makes of the members
/// of an element-scoped filter.
pub(super) fn member_of(
    options: &JsonOptions,
    base: &JsonPath,
    relative: JsonPath,
) -> Result<JsonPath, Error> {
    if !relative.is_positional() {
        return Err(Error::bad_source(Reason::JsonPathWildcard));
    }
    let full = relative
        .segments()
        .iter()
        .fold(base.clone(), |at, segment| at.then(segment.clone()));
    if full.segments().len() > crate::json::MAX_DEPTH {
        return Err(term(TermError::JsonTooDeep));
    }
    ordered_path_of(options, full)
}

/// `eq_at`'s input: a scalar at a path read through a selector.
fn read_eq_at(input: &ValueFrame) -> Result<Input, Error> {
    let at: AtInput = read_frame(input)?;
    let path = selector_path(&at.path)?;
    let value = at.json.parse()?;
    if matches!(value.0, Value::Object(_) | Value::Array(_)) {
        return Err(term(TermError::JsonValueNotScalar));
    }
    Ok(Input::At(path, value))
}

/// An ordering's input: a leaf the index orders at an ordered path.
fn read_ordering(options: &JsonOptions, input: &ValueFrame) -> Result<Input, Error> {
    let at: AtInput = read_frame(input)?;
    let path = ordered_path(options, &at.path)?;
    let value = at.json.parse()?;
    leaf(&value.0)?;
    Ok(Input::At(path, value))
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

/// A path the index orders, which names no position.
///
/// A position here is the index's own refusal,
/// [`TermError::JsonOrderingAtPosition`], the one the typed
/// `op::AtPath` orderings and [`JsonOptions::ordering`] give, so a
/// binding and a Rust caller see one error for one mistake. `eq_at` and
/// `selector` have no such refusal in the index (a typed equality reads a
/// position as the wildcard), so the data plan's own,
/// [`Reason::JsonPathPosition`], is what refuses one there.
fn ordered_path(options: &JsonOptions, text: &str) -> Result<JsonPath, Error> {
    ordered_path_of(options, path(text)?)
}

/// [`ordered_path`] of a path already parsed.
pub(super) fn ordered_path_of(options: &JsonOptions, path: JsonPath) -> Result<JsonPath, Error> {
    if path.names_a_position() {
        Err(term(TermError::JsonOrderingAtPosition))
    } else if options.orders(&path) {
        Ok(path)
    } else {
        Err(term(TermError::JsonPathNotOrdered))
    }
}

/// A leaf the index orders: a number or a string.
pub(super) fn leaf(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(_) | Value::String(_) => Ok(()),
        _ => Err(term(TermError::JsonLeafNotOrdered)),
    }
}

/// Check a JSON operator's input without a cipher: what [`derive`]
/// refuses from the input alone (its shape, its paths and values, a path
/// deeper than a document). The limits a subtree read's key hits as it is
/// built, a wildcard expanding too wide or a path too deep for its
/// tokens (`JsonWildcardTooWide`, `JsonTooWide`, `JsonTooDeep`), are
/// [`derive`]'s, after the keyset is resolved.
pub(super) fn check(op: OpSpec, options: &JsonOptions, input: &ValueFrame) -> Result<(), Error> {
    read_input(op, options, input).map(drop)
}

/// The JSON index's terms of `value` under the column, as the stored
/// document's were derived.
fn terms<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    options: &JsonOptions,
    label: &Label,
    value: Value,
) -> Pending<'a, crate::json::JsonTerms, K> {
    keyset.run(
        Index::<Value>::operation::<K, Owned>(&Json::new(options.clone()))
            .under(NonEmpty::from(label.clone())),
        value,
        DeclaredContext::default(),
    )
}

pub(super) fn eql<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, crate::Error> {
    serde_json::to_vec(value).map_err(|error| crate::Error::Other(Box::new(error)))
}

/// Derive a JSON operator's operand for one input, under the field's
/// column and options. Derived locally: the pending carries no request.
pub(super) fn derive<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    label: &Label,
    options: &JsonOptions,
    op: OpSpec,
    input: &ValueFrame,
) -> Result<Pending<'a, Operand, K>, Error> {
    derive_input(keyset, label, options, op, read_input(op, options, input)?)
}

/// Derive an operand for an input already read and checked: what
/// [`derive`] does past reading, and what `match` does for each of its
/// leaves.
pub(super) fn derive_input<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    label: &Label,
    options: &JsonOptions,
    op: OpSpec,
    input: Input,
) -> Result<Pending<'a, Operand, K>, Error> {
    let column = || NonEmpty::from(label.clone());
    Ok(match input {
        Input::Document(document) => terms(keyset, options, label, document.0.clone())
            .try_map(|terms| eql(&JsonQuery::of_terms(terms)).map(Operand::One)),
        Input::At(path, value) if op == OpSpec::EqAt => {
            terms(keyset, options, label, path.holding(value.0.clone()))
                .try_map(|terms| eql(&JsonQuery::at_path(terms)).map(Operand::One))
        }
        Input::At(path, value) => terms(keyset, options, label, path.holding(value.0.clone()))
            .try_map(|terms| eql(&JsonLeafQuery::of_leaf(&terms)).map(Operand::One)),
        Input::Between(path, low, high) => {
            terms(keyset, options, label, path.holding(low.0.clone()))
                .zip(terms(keyset, options, label, path.holding(high.0.clone())))
                .try_map(|(lo, hi)| {
                    Ok(Operand::Range {
                        lo: eql(&JsonLeafQuery::of_leaf(&lo))?,
                        hi: eql(&JsonLeafQuery::of_leaf(&hi))?,
                    })
                })
        }
        Input::Path(path) if op == OpSpec::Selector => {
            let selector = keyset.json_selector_now(&path, column())?;
            Pending::ready(keyset, Ok(Operand::Text(selector.to_string())))
        }
        Input::Path(path) => {
            // A path with no wildcard names one node: its key holds the
            // one token, and nothing that covers a node above it.
            let key = keyset.json_subtree_key_now(
                &path,
                options,
                JsonSubtreeKey::DEFAULT_BOUND,
                column(),
            )?;
            let [token]: [String; 1] = key.tokens().try_into().map_err(|_| Error::Internal)?;
            Pending::ready(keyset, Ok(Operand::Text(token)))
        }
        Input::Read(path, bound) => {
            let key = keyset.json_subtree_key_now(&path, options, bound, column())?;
            Pending::ready(keyset, Ok(Operand::TextList(key.tokens())))
        }
        Input::Elements(bound, predicates) => elements(keyset, label, options, bound, &predicates)?,
        Input::Predicate(node) => super::json_predicate::derive(keyset, label, options, *node)?,
    })
}

/// One member of an `element_match` operand: the tokens of a read of the
/// member's full path, probes included, and its bounds, each a leaf
/// operand. `eql_v4.query_json_elements` holds a list of them as `{"m"}`.
#[derive(serde::Serialize)]
struct MemberOperand {
    t: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gt: Option<JsonLeafQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gte: Option<JsonLeafQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lt: Option<JsonLeafQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lte: Option<JsonLeafQuery>,
}

/// `element_match`'s operand, `eql_v4.query_json_elements`.
#[derive(serde::Serialize)]
struct ElementsOperand {
    m: Vec<MemberOperand>,
}

impl MemberOperand {
    /// The member reading `tokens` that compares as `compare`, with the
    /// leaf operands of its values in order: one for a comparison, the
    /// low's then the high's for `between` (`compare` `None`). Equality is
    /// both inclusive bounds at its one value.
    fn new(tokens: Vec<String>, compare: Option<Compare>, leaves: Vec<JsonLeafQuery>) -> Self {
        let mut member = Self {
            t: tokens,
            gt: None,
            gte: None,
            lt: None,
            lte: None,
        };
        let mut leaves = leaves.into_iter();
        match compare {
            Some(Compare::Eq) => {
                member.gte = leaves.next();
                member.lte = member.gte.clone();
            }
            Some(Compare::Lt) => member.lt = leaves.next(),
            Some(Compare::Lte) => member.lte = leaves.next(),
            Some(Compare::Gt) => member.gt = leaves.next(),
            Some(Compare::Gte) => member.gte = leaves.next(),
            None => {
                member.gte = leaves.next();
                member.lte = leaves.next();
            }
        }
        member
    }
}

/// `element_match`'s operand: for each predicate, the tokens of a subtree
/// read of its full path at `bound`, as `subtree` derives them, and the
/// leaf operand of each of its values, as the orderings derive them. The
/// reads share the path and the bound, so the `k`-th token of every member
/// names a field of one element, and each member's last names the element
/// at the bound: the probe.
fn elements<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    label: &Label,
    options: &JsonOptions,
    bound: u32,
    predicates: &[Predicate],
) -> Result<Pending<'a, Operand, K>, Error> {
    let mut members = Vec::with_capacity(predicates.len());
    for predicate in predicates {
        let tokens = keyset
            .json_subtree_key_now(
                &predicate.path,
                options,
                bound,
                NonEmpty::from(label.clone()),
            )?
            .tokens();
        let leaf = |value: &Parsed| {
            terms(
                keyset,
                options,
                label,
                predicate.path.holding(value.0.clone()),
            )
            .map(|terms| JsonLeafQuery::of_leaf(&terms))
        };
        let (compare, leaves) = match &predicate.bounds {
            Bounds::One(compare, value) => (Some(*compare), vec![leaf(value)]),
            Bounds::Between(low, high) => (None, vec![leaf(low), leaf(high)]),
        };
        members.push(
            Pending::all(keyset, leaves)
                .map(move |leaves| MemberOperand::new(tokens, compare, leaves)),
        );
    }
    Ok(Pending::all(keyset, members).try_map(|m| eql(&ElementsOperand { m }).map(Operand::One)))
}

/// A read to open, as the request that prepared it names it: the
/// operator, the path and, for a subtree read, the wildcard bound. What a
/// binding keeps from preparing the read and hands back with its rows; the
/// engine derives the selector or the key again from it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    operation: String,
    path: String,
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
}

/// Read and check a read's request and its rows: everything [`open`]
/// refuses before it derives anything. A selector's group holds one entry
/// or none.
fn read_open(request: &ValueFrame, rows: &ValueFrame) -> Result<(Read, Vec<Vec<JsonNode>>), Error> {
    let request: ReadRequest = read_frame(request)?;
    let read = match OpSpec::parse(&request.operation) {
        Some(OpSpec::Selector) if request.wildcard_bound.is_none() => {
            Read::Selector(selector_path(&request.path)?)
        }
        Some(OpSpec::Subtree) => Read::Subtree(
            path(&request.path)?,
            request
                .wildcard_bound
                .unwrap_or(JsonSubtreeKey::DEFAULT_BOUND),
        ),
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
    if matches!(read, Read::Selector(_)) && groups.iter().any(|group| group.len() > 1) {
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
/// from the request.
enum Opener {
    Selector(crate::json::JsonSelector),
    Subtree(JsonSubtreeKey),
}

/// Open the rows a read returned against the request that prepared it,
/// under the field's column and options and through `keyset`, the keyset
/// whose index key derived the read, and that keyset alone: a document
/// sealed under another is refused before any key is retrieved. Each
/// group of rows is one database row's: for `selector`, the entry `->`
/// returned or none (SQL `NULL`); for `subtree`, the rows
/// `json_tree_subtree` returned. Every group opens to a list of JSON
/// texts: for `selector`, the scalar or none, and for `subtree`, one value
/// per concrete path the read named that the row has, in document order.
/// One key request for every group.
///
/// # Errors
///
/// [`Error::Source`] ([`Reason::JsonInput`]) for a request or rows that
/// do not parse, an operation that is not `selector` or `subtree`, a
/// `wildcard_bound` on a `selector`, or a selector group of more than one
/// entry; [`Error::Cipher`] for the read's own refusals (a path that does
/// not parse, a wildcard that expands too far). A row that is not the one
/// the read asked for fails the pending
/// ([`crate::Error::JsonWrongEntry`]), as does a wildcard read of an array
/// longer than the bound ([`crate::Error::JsonWildcardTruncated`]). A
/// `selector` entry that does not open alone, a container with members or
/// an altered entry, is [`crate::Error::JsonNotALeaf`].
pub(super) fn open<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    label: &Label,
    options: &JsonOptions,
    request: &ValueFrame,
    rows: &ValueFrame,
) -> Result<Pending<'a, ValueFrame, K>, Error> {
    let (read, groups) = read_open(request, rows)?;
    let column = || NonEmpty::from(label.clone());
    let opener = match read {
        Read::Selector(path) => Opener::Selector(keyset.json_selector_now(&path, column())?),
        Read::Subtree(path, bound) => {
            Opener::Subtree(keyset.json_subtree_key_now(&path, options, bound, column())?)
        }
    };
    let context = || AeadContext::from(NonEmpty::from(label.clone()));
    // Opened through the client, confined to the deriving keyset, as a
    // record's leaves are under `Scope::Keyset`: the read's key is that
    // keyset's, so a document sealed under another cannot answer it.
    let opener_cipher = keyset.cipher();
    let confine = keyset.keyset_id();
    let confined = |pending: Pending<'a, Vec<Value>, K>| pending.scoped_to(confine);
    let mut pendings: Vec<Pending<'a, Vec<Value>, K>> = Vec::with_capacity(groups.len());
    for nodes in groups {
        pendings.push(match &opener {
            Opener::Selector(selector) => match <[JsonNode; 1]>::try_from(nodes) {
                Ok([node]) => confined(
                    opener_cipher
                        .decrypt_as::<Value, JsonExtracted>(selector.open(node), context())
                        .map(|value| vec![value]),
                ),
                // `read_open` allows a selector group one entry or none.
                Err(_) => Pending::ready(keyset, Ok(Vec::new())),
            },
            Opener::Subtree(key) => confined(
                opener_cipher.decrypt_as::<Vec<Value>, JsonSubtree>(key.open(nodes), context()),
            ),
        });
    }
    Ok(Pending::all(keyset, pendings).try_map(opened_frame))
}

/// The opened groups as a frame: a list per group of each value's JSON
/// text, as bytes. Each value is wiped once its text is written, and each
/// text once the frame holds it.
fn opened_frame(mut groups: Vec<Vec<Value>>) -> Result<ValueFrame, crate::Error> {
    let texts: Result<Vec<Vec<Protected<Vec<u8>>>>, crate::Error> = groups
        .iter()
        .map(|group| {
            group
                .iter()
                .map(|value| {
                    crate::json::to_text(value)
                        .map(Protected::new)
                        .map_err(|error| crate::Error::Other(Box::new(error)))
                })
                .collect()
        })
        .collect();
    groups.iter_mut().flatten().for_each(wipe_value);
    ValueFrame::of(&texts?).map_err(|error| crate::Error::Other(Box::new(error)))
}
