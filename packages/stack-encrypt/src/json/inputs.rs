//! The inputs of the JSON operators, the checks on them, and the
//! derivation of their operands: one definition, which the dynamic
//! interface reads into from a binding's frames and a field reference's typed
//! JSON queries build directly. Compiled without the `dynamic` feature.
//!
//! An [`Input`] is checked when it is built, against the field's options:
//! everything [`derive`] would refuse before it derives anything is refused
//! there, so a refused query requests no key. [`derive`] then derives the
//! operand under the field's query context ([`Under`]) and gives it typed
//! ([`Derived`]). The dynamic interface writes that as the operand a binding
//! binds; a field reference hands it to the field's own query type.
//!
//! The rules each operator applies are documented with the dynamic
//! interface's JSON operators (`stack_encrypt::dynamic`, with the `dynamic`
//! feature), where a binding meets them.

use serde_json::Value;
use zeroize::Zeroizing;

use super::predicate::Node;
use super::{
    wipe_value, IndexPath, JsonElementsMember, JsonElementsQuery, JsonLeafQuery, JsonOptions,
    JsonPath, JsonPredicateQuery, JsonQuery, JsonSelector, JsonSubtreeKey,
};
use crate::refusal::{Error, Reason};
use crate::sem::TermError;
use crate::target::{AeadContext, CallerContext, DeclaredContext, Owned};
use crate::{ContextPiece, KeysetCipher, Label, NonEmpty, Pending};

/// A document parsed from an input, wiped when it drops.
#[derive(PartialEq)]
pub(crate) struct Parsed(pub(crate) Value);

impl Drop for Parsed {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

impl Parsed {
    /// The document `value` holds, which the input then wipes when it drops.
    pub(crate) fn of(value: Value) -> Self {
        Self(value)
    }

    /// The document, moved out to a new owner, which wipes it in turn.
    pub(crate) fn take(mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}

/// The reason a JSON text refusal is reported with.
pub(crate) fn json_reason(error: crate::json::JsonTextError) -> Reason {
    use crate::json::JsonTextError as E;
    match error {
        E::Syntax { .. } => Reason::JsonSyntax,
        E::DuplicateKey { .. } => Reason::JsonDuplicateKey,
        E::IntegerRange => Reason::JsonIntegerRange,
    }
}

/// How a predicate of `element_match` compares its field with one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Compare {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
}

/// A predicate's bounds, as its input gives them.
#[derive(PartialEq)]
pub(crate) enum Bounds {
    /// One value, compared by the predicate's `op`.
    One(Compare, Parsed),
    /// `between`: the low bound then the high, both inclusive.
    Between(Parsed, Parsed),
}

/// One predicate of `element_match`, checked: the full path of the
/// element's field, which the field orders, and its bounds.
#[derive(PartialEq)]
pub(crate) struct Predicate {
    pub(crate) path: JsonPath,
    pub(crate) bounds: Bounds,
}

/// An operator's input, checked: everything [`derive`] would refuse
/// before it derives anything. `match`'s is its predicate compiled to a tree
/// of the other operators' inputs.
#[derive(PartialEq)]
pub(crate) enum Input {
    /// `contains`, `contained_by`: a document.
    Document(Parsed),
    /// `eq_at`: a scalar at a path read through a selector.
    EqAt(JsonPath, Parsed),
    /// An ordering, `lt_at` to `gte_at`: a leaf at an ordered path, and how
    /// it compares. Never [`Compare::Eq`].
    Ordering(Compare, JsonPath, Parsed),
    /// `between_at`: two leaves at an ordered path, low then high.
    Between(JsonPath, Parsed, Parsed),
    /// `selector`: a path read through a selector.
    Selector(JsonPath),
    /// `children`, `child_count`: a path that names one node.
    Node(JsonPath),
    /// `subtree`: a path and the bound its wildcards expand to. Read by
    /// the dynamic interface alone.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    Read(JsonPath, u32),
    /// `element_match`: the bound and one or more predicates.
    Elements(u32, Vec<Predicate>),
    /// `match`: a compiled predicate.
    Predicate(Box<Node>),
}

impl Input {
    /// The operator's name in a variant's spelling, which a compiled
    /// predicate's `Debug` prints for a leaf: never the input's values.
    pub(crate) fn variant(&self) -> &'static str {
        match self {
            Self::Document(_) => "Contains",
            Self::EqAt(..) => "EqAt",
            Self::Ordering(Compare::Lt, ..) => "LtAt",
            Self::Ordering(Compare::Lte, ..) => "LteAt",
            Self::Ordering(Compare::Gt, ..) => "GtAt",
            Self::Ordering(Compare::Gte | Compare::Eq, ..) => "GteAt",
            Self::Between(..) => "BetweenAt",
            Self::Selector(_) => "Selector",
            Self::Node(_) => "Children",
            Self::Read(..) => "Subtree",
            Self::Elements(..) => "ElementMatch",
            Self::Predicate(_) => "Match",
        }
    }

    /// The operator's wire name, as the dynamic interface spells it.
    #[cfg(test)]
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Document(_) => "contains",
            Self::EqAt(..) => "eq_at",
            Self::Ordering(Compare::Lt, ..) => "lt_at",
            Self::Ordering(Compare::Lte, ..) => "lte_at",
            Self::Ordering(Compare::Gt, ..) => "gt_at",
            Self::Ordering(Compare::Gte | Compare::Eq, ..) => "gte_at",
            Self::Between(..) => "between_at",
            Self::Selector(_) => "selector",
            Self::Node(_) => "children",
            Self::Read(..) => "subtree",
            Self::Elements(..) => "element_match",
            Self::Predicate(_) => "match",
        }
    }

    /// `eq_at`'s input: a scalar at a path read through a selector.
    pub(crate) fn eq_at(path: &str, value: Parsed) -> Result<Self, Error> {
        let path = selector_path(path)?;
        scalar(&value.0)?;
        Ok(Self::EqAt(path, value))
    }

    /// An ordering's input: a leaf the index orders at an ordered path.
    /// `compare` is never [`Compare::Eq`]; equality is [`eq_at`](Self::eq_at).
    pub(crate) fn ordering(
        options: &JsonOptions,
        compare: Compare,
        path: &str,
        value: Parsed,
    ) -> Result<Self, Error> {
        let path = ordered_path(options, path)?;
        leaf(&value.0)?;
        Ok(Self::Ordering(compare, path, value))
    }

    /// `between_at`'s input: two leaves the index orders at an ordered path.
    pub(crate) fn between(
        options: &JsonOptions,
        path: &str,
        low: Parsed,
        high: Parsed,
    ) -> Result<Self, Error> {
        let path = ordered_path(options, path)?;
        leaf(&low.0)?;
        leaf(&high.0)?;
        Ok(Self::Between(path, low, high))
    }

    /// `element_match`'s input: the bound, and one or more predicates on
    /// the fields of the elements at `base` ([`elements_base`]).
    pub(crate) fn elements(bound: Option<u32>, predicates: Vec<Predicate>) -> Result<Self, Error> {
        let bound = wildcard_bound(bound)?;
        if predicates.is_empty() {
            return Err(Error::bad_source(Reason::JsonNoPredicates));
        }
        Ok(Self::Elements(bound, predicates))
    }

    /// `match`'s input: a jsonpath predicate, its variables as one JSON
    /// object (the `vars` jsonb `jsonb_path_match` takes) and the bound its
    /// element-scoped leaves are read to. The predicate is compiled here, so
    /// every refusal it can meet is met before anything is derived.
    pub(crate) fn predicate(
        options: &JsonOptions,
        text: &str,
        vars: &Value,
        bound: Option<u32>,
    ) -> Result<Self, Error> {
        let bound = wildcard_bound(bound)?;
        if !vars.is_object() {
            return Err(Error::bad_source(Reason::JsonInput));
        }
        Ok(Self::Predicate(Box::new(super::predicate::compile(
            text, vars, options, bound,
        )?)))
    }
}

/// The path of an array's elements that `element_match` reads: a path with
/// a wildcard, and no position.
pub(crate) fn elements_base(text: &str) -> Result<JsonPath, Error> {
    let base = path(text)?;
    if base.is_positional() {
        return Err(Error::bad_source(Reason::JsonPathNoWildcard));
    }
    if base.names_a_position() {
        return Err(term(TermError::JsonOrderingAtPosition));
    }
    Ok(base)
}

/// One predicate of `element_match`: its member's full path below `base`,
/// which the field must order, and its bounds, each a leaf the index
/// orders.
pub(crate) fn member_predicate(
    options: &JsonOptions,
    base: &JsonPath,
    member: &str,
    bounds: Bounds,
) -> Result<Predicate, Error> {
    let path = member_path(options, base, member)?;
    match &bounds {
        Bounds::One(_, value) => leaf(&value.0)?,
        Bounds::Between(low, high) => {
            leaf(&low.0)?;
            leaf(&high.0)?;
        }
    }
    Ok(Predicate { path, bounds })
}

/// A path from an input. A path with more steps than a document has
/// levels names no node, and the operators that build the document
/// holding a value there (`eq_at`, the orderings) would build one as deep
/// as the path, whose recursive drop could overflow the stack: it is
/// refused as too deep before anything is built, for every operator.
pub(crate) fn path(text: &str) -> Result<JsonPath, Error> {
    let path =
        JsonPath::parse(text).map_err(|error| Error::Cipher(TermError::JsonPath(error).into()))?;
    if path.segments().len() > crate::json::MAX_DEPTH {
        return Err(term(TermError::JsonTooDeep));
    }
    Ok(path)
}

/// A path whose operand is a selector, which reads a position as the
/// wildcard.
pub(crate) fn selector_path(text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    if path.names_a_position() {
        return Err(Error::bad_source(Reason::JsonPathPosition));
    }
    Ok(path)
}

/// A path that names one node: no wildcard.
pub(crate) fn node_path(text: &str) -> Result<JsonPath, Error> {
    let path = path(text)?;
    // `is_positional`: every array step names a position, so the path
    // has no wildcard and names at most one node.
    if path.is_positional() {
        Ok(path)
    } else {
        Err(Error::bad_source(Reason::JsonPathWildcard))
    }
}

pub(crate) fn term(error: TermError) -> Error {
    Error::Cipher(error.into())
}

/// The wildcard bound an input names, or the default: never `0`, which
/// would send the probe alone, so an element predicate could never be true.
pub(crate) fn wildcard_bound(bound: Option<u32>) -> Result<u32, Error> {
    match bound.unwrap_or(JsonSubtreeKey::DEFAULT_BOUND) {
        0 => Err(Error::bad_source(Reason::JsonWildcardBoundZero)),
        bound => Ok(bound),
    }
}

/// A member's full path: `base` and then the member's steps, read as a
/// path relative to an element (`name`, `address.city`, `["a b"]`). A
/// member names one field of each element, so it has no wildcard of its
/// own, and the full path is an ordering's: no position, and ordered. A
/// member that does not parse is refused at an offset into the member's
/// own text.
pub(crate) fn member_path(
    options: &JsonOptions,
    base: &JsonPath,
    member: &str,
) -> Result<JsonPath, Error> {
    let prefix = if member.starts_with('[') { "$" } else { "$." };
    // Sized before it is written, and wiped: the member names keys.
    let mut rooted = Zeroizing::new(String::with_capacity(prefix.len() + member.len()));
    rooted.push_str(prefix);
    rooted.push_str(member);
    let relative = JsonPath::parse(&rooted).map_err(|error| {
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
pub(crate) fn member_of(
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

/// A path the index orders, which names no position.
///
/// A position here is the index's own refusal,
/// [`TermError::JsonOrderingAtPosition`], the one the typed
/// `op::AtPath` orderings and [`JsonOptions::ordering`] give, so a
/// binding and a Rust caller see one error for one mistake. `eq_at` and
/// `selector` have no such refusal in the index (a typed equality reads a
/// position as the wildcard), so the data plan's own,
/// [`Reason::JsonPathPosition`], is what refuses one there.
pub(crate) fn ordered_path(options: &JsonOptions, text: &str) -> Result<JsonPath, Error> {
    ordered_path_of(options, path(text)?)
}

/// [`ordered_path`] of a path already parsed.
pub(crate) fn ordered_path_of(options: &JsonOptions, path: JsonPath) -> Result<JsonPath, Error> {
    if path.names_a_position() {
        Err(term(TermError::JsonOrderingAtPosition))
    } else if options.orders(&path) {
        Ok(path)
    } else {
        Err(term(TermError::JsonPathNotOrdered))
    }
}

/// A scalar, what equality at a path takes: not an object or an array.
pub(crate) fn scalar(value: &Value) -> Result<(), Error> {
    match value {
        Value::Object(_) | Value::Array(_) => Err(term(TermError::JsonValueNotScalar)),
        _ => Ok(()),
    }
}

/// A leaf the index orders: a number or a string.
pub(crate) fn leaf(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(_) | Value::String(_) => Ok(()),
        _ => Err(term(TermError::JsonLeafNotOrdered)),
    }
}

/// Where a document field's queries and reads run: under the field's
/// label, then the scopes and the bindings of its plan, as the document
/// was sealed.
///
/// For example, take the field `profile` of the table `users`, in a plan
/// whose caller added the tenant 7 as a scope and the row 9 as a binding.
/// A selector, a read key and every other term derive under
/// `users/profile`, then 7: the query context. An entry that a read
/// returns opens under `users/profile`, then 7, then 9: the stored
/// context.
#[derive(Clone)]
pub(crate) struct Under<'p> {
    label: &'p Label,
    /// The plan's scopes, then its bindings.
    parts: DeclaredContext,
}

impl<'p> Under<'p> {
    /// The field with the label `label`, in a plan whose scopes and
    /// bindings are `parts`.
    pub(crate) fn new(label: &'p Label, parts: DeclaredContext) -> Self {
        Self { label, parts }
    }

    pub(crate) fn column(&self) -> NonEmpty<Label> {
        NonEmpty::from(self.label.clone())
    }

    /// The label and the parts, owned: what a pending that is built when
    /// it settles keeps, to name the field again with [`Under::new`].
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn owned(&self) -> (Label, DeclaredContext) {
        (self.label.clone(), self.parts.clone())
    }

    /// The field's context: its label, then the plan's scopes and
    /// bindings.
    pub(crate) fn context(&self) -> CallerContext {
        self.parts.clone().under(self.column())
    }

    /// The query context, the label and then the scopes, which a selector
    /// and a read key derive under. A binding is not in it.
    pub(crate) fn query(&self) -> Result<NonEmpty<ContextPiece<'static>>, Error> {
        Ok(CallerContext::query_nonempty(self.context().validated()?))
    }

    /// The stored context, the query context and then the bindings, which
    /// an entry opens under.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn stored(&self) -> AeadContext {
        AeadContext::from(self.context())
    }
}

/// The JSON index's terms of `value` under the field's query context, as
/// the stored document's were derived.
fn terms<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    options: &JsonOptions,
    under: &Under<'_>,
    value: Value,
) -> Pending<'a, crate::json::JsonTerms, K> {
    keyset.run(
        crate::target::json_terms::<K, Owned>(options.clone()).under(under.column()),
        value,
        under.parts.clone(),
    )
}

/// An operand, as [`derive`] gives it: what the dynamic interface writes as
/// the operand a binding binds, and what a field reference hands to the field's
/// own query type.
pub(crate) enum Derived {
    /// `contains`, `contained_by`, `eq_at`: a containment needle.
    Query(JsonQuery),
    /// An ordering: the path's selector and the leaf's ordering term.
    Leaf(JsonLeafQuery),
    /// `between_at`: the low bound's leaf operand, then the high's.
    Range(JsonLeafQuery, JsonLeafQuery),
    /// `selector`: the path's selector.
    Selector(JsonSelector),
    /// `children`, `child_count`: the key of a path that names one node,
    /// which holds that node's one token.
    Node(JsonSubtreeKey),
    /// `subtree`: the read's key. Read by the dynamic interface alone.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    Read(JsonSubtreeKey),
    /// `element_match`.
    Elements(JsonElementsQuery),
    /// `match`.
    Predicate(JsonPredicateQuery),
}

/// Derive an operand for an input already checked, under the field's query
/// context and options. Derived locally: the pending carries no request.
pub(crate) fn derive<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    input: Input,
) -> Result<Pending<'a, Derived, K>, Error> {
    Ok(match input {
        Input::Document(document) => {
            // Checked before the clone, which recurses once per level: a
            // document a caller built deeper than the index reads is
            // refused as the walk would refuse it, not cloned first.
            if !super::text::nests_within(&document.0, super::MAX_DEPTH) {
                return Err(term(TermError::JsonTooDeep));
            }
            terms(keyset, options, under, document.0.clone())
                .map(|terms| Derived::Query(JsonQuery::of_terms(terms)))
        }
        Input::EqAt(path, value) => terms(keyset, options, under, path.holding(value.0.clone()))
            .map(|terms| Derived::Query(JsonQuery::at_path(terms))),
        Input::Ordering(_, path, value) => {
            terms(keyset, options, under, path.holding(value.0.clone()))
                .map(|terms| Derived::Leaf(JsonLeafQuery::of_leaf(&terms)))
        }
        Input::Between(path, low, high) => {
            terms(keyset, options, under, path.holding(low.0.clone()))
                .zip(terms(keyset, options, under, path.holding(high.0.clone())))
                .map(|(lo, hi)| {
                    Derived::Range(JsonLeafQuery::of_leaf(&lo), JsonLeafQuery::of_leaf(&hi))
                })
        }
        // The three below derive under the keyset's index key. With the
        // keyset loaded they derive now, so a refusal is this call's own
        // error. With a keyset that is not loaded yet, the pending
        // derives when it has loaded the keyset, and a refusal is its
        // error.
        Input::Selector(path) => match keyset.loaded_state() {
            Some(_) => {
                let selector = keyset.json_selector_now(&path, under.query()?)?;
                Pending::ready(keyset, Ok(Derived::Selector(selector)))
            }
            None => keyset
                .json_selector(&path, under.query()?)
                .map(Derived::Selector),
        },
        Input::Node(path) => match keyset.loaded_state() {
            Some(_) => {
                // A path with no wildcard names one node: its key holds the
                // one token, and nothing that covers a node above it.
                let key = keyset.json_subtree_key_now(
                    &path,
                    options,
                    JsonSubtreeKey::DEFAULT_BOUND,
                    under.query()?,
                )?;
                if key.tokens().len() != 1 {
                    return Err(Error::Internal);
                }
                Pending::ready(keyset, Ok(Derived::Node(key)))
            }
            None => keyset
                .json_subtree_key(&path, options, under.query()?)
                .try_map(|key| {
                    if key.tokens().len() != 1 {
                        return Err(crate::Error::Other(Box::new(Error::Internal)));
                    }
                    Ok(Derived::Node(key))
                }),
        },
        Input::Read(path, bound) => match keyset.loaded_state() {
            Some(_) => {
                let key = keyset.json_subtree_key_now(&path, options, bound, under.query()?)?;
                Pending::ready(keyset, Ok(Derived::Read(key)))
            }
            None => keyset
                .json_subtree_key_with_bound(&path, options, bound, under.query()?)
                .map(Derived::Read),
        },
        Input::Elements(bound, predicates) => elements(keyset, under, options, bound, &predicates)?,
        Input::Predicate(node) => {
            super::predicate::derive(keyset, under, options, *node)?.map(Derived::Predicate)
        }
    })
}

/// `element_match`'s operand: for each predicate, the tokens of a subtree
/// read of its full path at `bound`, as `subtree` derives them, and the
/// leaf operand of each of its values, as the orderings derive them. The
/// reads share the path and the bound, so the `k`-th token of every member
/// names a field of one element, and each member's last names the element
/// at the bound: the probe.
pub(crate) fn elements_operand<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    bound: u32,
    predicates: &[Predicate],
) -> Result<Pending<'a, JsonElementsQuery, K>, Error> {
    let mut members = Vec::with_capacity(predicates.len());
    for predicate in predicates {
        // With the keyset loaded, the read's tokens are derived now, as
        // they always were. With a keyset that is not loaded yet,
        // the member's pending derives them when it has loaded the keyset.
        let tokens = match keyset.loaded_state() {
            Some(_) => Some(
                keyset
                    .json_subtree_key_now(&predicate.path, options, bound, under.query()?)?
                    .tokens(),
            ),
            None => None,
        };
        let leaf = |value: &Parsed| {
            terms(
                keyset,
                options,
                under,
                predicate.path.holding(value.0.clone()),
            )
            .map(|terms| JsonLeafQuery::of_leaf(&terms))
        };
        let (compare, leaves) = match &predicate.bounds {
            Bounds::One(compare, value) => (Some(*compare), vec![leaf(value)]),
            Bounds::Between(low, high) => (None, vec![leaf(low), leaf(high)]),
        };
        members.push(match tokens {
            Some(tokens) => {
                Pending::all(keyset, leaves).map(move |leaves| member(tokens, compare, leaves))
            }
            None => keyset
                .json_subtree_key_with_bound(&predicate.path, options, bound, under.query()?)
                .zip(Pending::all(keyset, leaves))
                .map(move |(key, leaves)| member(key.tokens(), compare, leaves)),
        });
    }
    Ok(Pending::all(keyset, members).map(JsonElementsQuery::of))
}

fn elements<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    bound: u32,
    predicates: &[Predicate],
) -> Result<Pending<'a, Derived, K>, Error> {
    Ok(elements_operand(keyset, under, options, bound, predicates)?.map(Derived::Elements))
}

/// The member reading `tokens` that compares as `compare`, with the leaf
/// operands of its values in order: one for a comparison, the low's then
/// the high's for `between` (`compare` `None`). Equality is both inclusive
/// bounds at its one value.
fn member(
    tokens: Vec<String>,
    compare: Option<Compare>,
    leaves: Vec<JsonLeafQuery>,
) -> JsonElementsMember {
    let mut member = JsonElementsMember {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> JsonPath {
        path("$.a").expect("a path")
    }

    fn one() -> Parsed {
        Parsed::of(Value::from(1))
    }

    /// Each input names its operator in both spellings: the variant a
    /// compiled predicate's `Debug` prints, and the wire name.
    #[test]
    fn every_input_names_its_operator() {
        let inputs = [
            (Input::Document(one()), "Contains", "contains"),
            (Input::EqAt(at(), one()), "EqAt", "eq_at"),
            (Input::Ordering(Compare::Lt, at(), one()), "LtAt", "lt_at"),
            (
                Input::Ordering(Compare::Lte, at(), one()),
                "LteAt",
                "lte_at",
            ),
            (Input::Ordering(Compare::Gt, at(), one()), "GtAt", "gt_at"),
            (
                Input::Ordering(Compare::Gte, at(), one()),
                "GteAt",
                "gte_at",
            ),
            (
                Input::Between(at(), one(), one()),
                "BetweenAt",
                "between_at",
            ),
            (Input::Selector(at()), "Selector", "selector"),
            (Input::Node(at()), "Children", "children"),
            (Input::Read(at(), 8), "Subtree", "subtree"),
            (
                Input::Elements(8, Vec::new()),
                "ElementMatch",
                "element_match",
            ),
            (
                Input::Predicate(Box::new(Node::Leaf(Input::Selector(at())))),
                "Match",
                "match",
            ),
        ];
        for (input, variant, name) in inputs {
            assert_eq!((input.variant(), input.name()), (variant, name));
        }
    }
}
