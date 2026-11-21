//! `match`'s predicate: the SQL/JSON path predicates the JSON index can
//! answer, compiled onto the inputs of the other JSON operators.
//!
//! The text is PostgreSQL's SQL/JSON path language, as `jsonb_path_match`
//! takes it ([SQL/JSON path language](https://www.postgresql.org/docs/current/functions-json.html#FUNCTIONS-SQLJSON-PATH)),
//! restricted to predicates the terms can answer:
//!
//! ```text
//! $.age >= $min                                   a comparison with a variable
//! $.name == "ann" || $."first name" != null       literals and a quoted key
//! !($.age < 18) && exists($.email)                negation and presence
//! $.tags[*] == $tag                               any element equals
//! $.orders[*].total > 100                         any element's field orders
//! exists($.contacts[*] ? (@.relationship == $r && @.calls > 5))
//!                                                 one element satisfies both
//! ```
//!
//! The dynamic interface's `match` operator, a field reference's
//! `predicate` and the `predicate!` macro all compile through it. The
//! grammar and the compilation are documented with the operator, in the
//! dynamic interface's JSON operators (`stack_encrypt::dynamic`, with the
//! `dynamic` feature). The grammar itself is `stack-encrypt-jsonpath`'s
//! ([`predicate::parse`]), which `predicate!` reads the text with when a
//! program compiles, so the two read one grammar: it refuses what it does
//! not read at the byte where it stops. This module holds the compiler
//! ([`compile`]), which binds the values and maps each comparison onto the
//! inputs `eq_at`, `selector`, the orderings and `element_match` take, so
//! that every leaf is derived by that operator's own code ([`derive`]).
//!
//! A refusal names a construct in the grammar's words and an offset, never
//! a slice of the text: a key name or a value in it can be customer data.
//! The text itself is the caller's buffer, wiped when it drops; the tree
//! holds offsets into it, the key names in [`JsonPath`]s, which wipe them,
//! and the values in [`Parsed`], which wipes them.

use serde_json::Value;
use stack_encrypt_jsonpath::predicate::{
    self, check_filter, construct, single_equality, Comparison, Expression, Operator, PathAt,
    PredicateError, PredicateErrorKind, ValueAt,
};

use super::inputs::{
    derive as derive_input, json_reason, leaf, member_of, ordered_path_of, Bounds, Compare,
    Derived, Input, Parsed, Predicate, Under,
};
use super::{parse_text, IndexPath, JsonOptions, JsonPath, JsonPredicateQuery};
use crate::refusal::{Error, Reason};
use crate::{KeysetCipher, Pending};

/// A grammar refusal as the crate's refusal: the same construct and
/// offset, under the [`Reason`] the dynamic interface reports for it.
impl From<PredicateError> for Error {
    fn from(refusal: PredicateError) -> Self {
        let reason = match refusal.kind {
            PredicateErrorKind::Syntax => Reason::JsonPredicateSyntax,
            PredicateErrorKind::TooDeep => Reason::JsonPredicateTooDeep,
            PredicateErrorKind::Position => Reason::JsonPathPosition,
            PredicateErrorKind::NotEqualAtWildcard => Reason::JsonPredicateNotEqualAtWildcard,
            PredicateErrorKind::FilterWithoutWildcard => Reason::JsonPathNoWildcard,
            PredicateErrorKind::MemberWildcard => Reason::JsonPathWildcard,
            // `Unsupported`, and any kind the grammar adds: a construct
            // the index cannot answer.
            _ => Reason::JsonPredicateUnsupported,
        };
        refusal_at(reason, refusal.construct, refusal.at)
    }
}

/// A refusal of the construct `construct` at the byte `at`, for `reason`.
fn refusal_at(reason: Reason, construct: &'static str, at: usize) -> Error {
    Error::Predicate {
        field: None,
        reason,
        construct,
        at,
    }
}

/// How an element-scoped condition compares; `None` for `!=`, which a
/// filter does not take.
fn compare_of(operator: Operator) -> Option<Compare> {
    match operator {
        Operator::Equal => Some(Compare::Eq),
        Operator::Less => Some(Compare::Lt),
        Operator::LessOrEqual => Some(Compare::Lte),
        Operator::Greater => Some(Compare::Gt),
        Operator::GreaterOrEqual => Some(Compare::Gte),
        Operator::NotEqual => None,
    }
}

/// A predicate compiled: a tree of the inputs of the operators whose
/// operands are its leaves.
#[derive(PartialEq)]
pub(crate) enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    /// One leaf: the input of the operator that derives it, checked.
    Leaf(Input),
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::And(children) => f.debug_tuple("And").field(children).finish(),
            Node::Or(children) => f.debug_tuple("Or").field(children).finish(),
            Node::Not(child) => f.debug_tuple("Not").field(child).finish(),
            // The input holds the predicate's values: the operator alone.
            Node::Leaf(input) => write!(f, "Leaf({})", input.variant()),
        }
    }
}

/// What a compilation reads besides the tree: the text the tree's
/// offsets are into, the variables, the field's options and the bound an
/// element leaf is read to.
struct Compiler<'c> {
    text: &'c str,
    vars: &'c serde_json::Map<String, Value>,
    options: &'c JsonOptions,
    bound: u32,
}

/// Compile a predicate's text under `vars`, a JSON object, for a field
/// under `options`, its element leaves read to `bound`.
///
/// # Errors
///
/// [`Error::Predicate`] for text the grammar does not read or a construct
/// it reads and the index cannot answer, at its offset; and the refusals
/// the leaves' own operators make of their inputs, such as
/// [`TermError::JsonPathNotOrdered`](crate::sem::TermError::JsonPathNotOrdered) for an ordering at a path the field
/// does not order.
pub(crate) fn compile(
    text: &str,
    vars: &Value,
    options: &JsonOptions,
    bound: u32,
) -> Result<Node, Error> {
    let empty = serde_json::Map::new();
    let compiler = Compiler {
        text,
        vars: vars.as_object().unwrap_or(&empty),
        options,
        bound,
    };
    let expression = predicate::parse(text)?;
    Ok(simplify(compiler.node(expression, false)?))
}

impl Compiler<'_> {
    /// The node for `ast`, which sits under an odd number of `!` when
    /// `negated`. `and` and `or` are monotone in each child, so only a `!`
    /// turns a child's NULL into a different row set than its false; see
    /// [`Compiler::comparison`].
    fn node(&self, expression: Expression, negated: bool) -> Result<Node, Error> {
        Ok(match expression {
            Expression::And(terms) => Node::And(
                terms
                    .into_iter()
                    .map(|t| self.node(t, negated))
                    .collect::<Result<_, _>>()?,
            ),
            Expression::Or(terms) => Node::Or(
                terms
                    .into_iter()
                    .map(|t| self.node(t, negated))
                    .collect::<Result<_, _>>()?,
            ),
            Expression::Not(inner) => Node::Not(Box::new(self.node(*inner, !negated)?)),
            Expression::Compare(comparison) => self.comparison(comparison, negated)?,
            Expression::Exists { path, filter: None } => Node::Leaf(Input::Selector(path.path)),
            Expression::Exists {
                path,
                filter: Some(conditions),
            } => self.filter(path, conditions)?,
        })
    }

    /// The value a literal or a variable holds.
    fn value(&self, value: &ValueAt) -> Result<Parsed, Error> {
        match value {
            ValueAt::Literal { start, end } => parse_text(&self.text.as_bytes()[*start..*end])
                .map(Parsed)
                .map_err(|error| refusal_at(json_reason(error), construct::VALUE, *start)),
            ValueAt::Variable { name, at } => self
                .vars
                .get(name.as_str())
                .map(|value| Parsed(value.clone()))
                .ok_or_else(|| {
                    refusal_at(
                        Reason::JsonPredicateUnknownVariable,
                        construct::VARIABLE,
                        *at,
                    )
                }),
        }
    }

    /// Whether `at` is a variable that holds an object or an array. Read
    /// in place, so a container is refused before [`value`](Self::value)
    /// clones it: a clone recurses once per level of the caller's value.
    fn holds_a_container(&self, at: &ValueAt) -> bool {
        matches!(
            at,
            ValueAt::Variable { name, .. }
                if matches!(self.vars.get(name.as_str()), Some(Value::Object(_) | Value::Array(_)))
        )
    }

    /// The value of `at`, a scalar: what equality takes.
    fn scalar(&self, at: &ValueAt) -> Result<Parsed, Error> {
        if self.holds_a_container(at) {
            return Err(value_type(at));
        }
        let value = self.value(at)?;
        // A variable was checked in place above; a literal, read from the
        // predicate's own text, is checked once it is parsed.
        if matches!(at, ValueAt::Literal { .. })
            && matches!(value.0, Value::Object(_) | Value::Array(_))
        {
            return Err(value_type(at));
        }
        Ok(value)
    }

    /// The value of `at`, a number or a string: what an ordering takes.
    fn ordered(&self, at: &ValueAt) -> Result<Parsed, Error> {
        if self.holds_a_container(at) {
            return Err(value_type(at));
        }
        let value = self.value(at)?;
        leaf(&value.0).map_err(|_| value_type(at))?;
        Ok(value)
    }

    /// `path op value`, under an odd number of `!` when `negated`.
    fn comparison(&self, comparison: Comparison, negated: bool) -> Result<Node, Error> {
        // `!=` over several elements is true when one differs, which
        // containment cannot say.
        comparison.refuse_not_equal_at_wildcard()?;
        let Comparison {
            path,
            operator,
            value,
            at,
        } = comparison;
        let wild = !path.path.is_positional();
        let compare = match operator {
            // `==`: containment of the value at the path, exact; at a
            // wildcard, of any element.
            Operator::Equal => return Ok(Node::Leaf(Input::EqAt(path.path, self.scalar(&value)?))),
            // `!=` at one node: a node there that is not the value.
            Operator::NotEqual => {
                let value = self.scalar(&value)?;
                return Ok(Node::And(vec![
                    Node::Leaf(Input::Selector(path.path.clone())),
                    Node::Not(Box::new(Node::Leaf(Input::EqAt(path.path, value)))),
                ]));
            }
            Operator::Less => Compare::Lt,
            Operator::LessOrEqual => Compare::Lte,
            Operator::Greater => Compare::Gt,
            Operator::GreaterOrEqual => Compare::Gte,
        };
        Ok(if wild {
            // An ordering at a wildcard: some element's field, which is
            // `element_match` on the array through the last wildcard.
            let value = self.ordered(&value)?;
            let (base, member) = path.element_member(at)?;
            let predicate = self.member(&base, member, compare, value)?;
            Node::Leaf(Input::Elements(self.bound, vec![predicate]))
        } else {
            // An ordering at one node: a node there whose leaf compares.
            // jsonpath answers false of an absent path, which the selector
            // gives, and false of a JSON null, where the ordering is NULL
            // (a null has no ordering term). Under an even number of `!`
            // the two pick the same rows, since `and` and `or` cannot turn
            // a child's NULL into true; under an odd number `!` turns false
            // into true and NULL into NULL, so the tree also asks that the
            // node is not null. That `null` needle tells the database which
            // rows hold null at the path, so it is sent only there.
            let value = self.ordered(&value)?;
            let path = ordered_path_of(self.options, path.path)?;
            let mut leaves = vec![Node::Leaf(Input::Selector(path.clone()))];
            if negated {
                leaves.push(Node::Not(Box::new(Node::Leaf(Input::EqAt(
                    path.clone(),
                    Parsed(Value::Null),
                )))));
            }
            leaves.push(Node::Leaf(Input::Ordering(compare, path, value)));
            Node::And(leaves)
        })
    }

    /// One field of an element-scoped predicate: its full path, which the
    /// field orders, and its bound.
    fn member(
        &self,
        base: &JsonPath,
        member: JsonPath,
        compare: Compare,
        value: Parsed,
    ) -> Result<Predicate, Error> {
        Ok(Predicate {
            path: member_of(self.options, base, member)?,
            bounds: Bounds::One(compare, value),
        })
    }

    /// `exists(path ? (conditions))`: some element at the path satisfies
    /// every condition. One equality is containment at the condition's
    /// path, exact; anything else is `element_match`, every condition on a
    /// field of one element.
    fn filter(&self, path: PathAt, conditions: Vec<Comparison>) -> Result<Node, Error> {
        check_filter(&path, &conditions)?;
        let base = path.path;
        if let Some(only) = single_equality(&conditions) {
            let full = only.path.path.segments().iter().fold(
                base.segments().to_vec(),
                |mut at, segment| {
                    at.push(segment.clone());
                    at
                },
            );
            return Ok(Node::Leaf(Input::EqAt(
                JsonPath::of(full),
                self.scalar(&only.value)?,
            )));
        }
        let mut predicates = Vec::with_capacity(conditions.len());
        for condition in conditions {
            condition.check_filter_condition()?;
            let Some(compare) = compare_of(condition.operator) else {
                return Err(Error::Internal);
            };
            let value = self.ordered(&condition.value)?;
            predicates.push(self.member(&base, condition.path.path, compare, value)?);
        }
        Ok(Node::Leaf(Input::Elements(self.bound, predicates)))
    }
}

fn value_type(at: &ValueAt) -> Error {
    refusal_at(Reason::JsonPredicateValueType, construct::VALUE, at.at())
}

/// The tree with every `and` in an `and` and every `or` in an `or` lifted
/// into its parent, a child equal to an earlier sibling dropped, a list of
/// one replaced by its child, and `not` of `not` by its child: each
/// preserves SQL's three-valued answer.
fn simplify(node: Node) -> Node {
    fn gather(children: Vec<Node>, lift: fn(Node) -> Result<Vec<Node>, Node>) -> Vec<Node> {
        let mut out: Vec<Node> = Vec::with_capacity(children.len());
        for child in children {
            let lifted = match lift(simplify(child)) {
                Ok(grandchildren) => grandchildren,
                Err(child) => vec![child],
            };
            for child in lifted {
                if !out.contains(&child) {
                    out.push(child);
                }
            }
        }
        out
    }
    let one_or = |mut children: Vec<Node>, wrap: fn(Vec<Node>) -> Node| {
        if children.len() == 1 {
            children.remove(0)
        } else {
            wrap(children)
        }
    };
    match node {
        Node::And(children) => one_or(
            gather(children, |node| match node {
                Node::And(children) => Ok(children),
                other => Err(other),
            }),
            Node::And,
        ),
        Node::Or(children) => one_or(
            gather(children, |node| match node {
                Node::Or(children) => Ok(children),
                other => Err(other),
            }),
            Node::Or,
        ),
        Node::Not(child) => match simplify(*child) {
            Node::Not(inner) => *inner,
            child => Node::Not(Box::new(child)),
        },
        leaf => leaf,
    }
}

/// The shape of a compiled tree with its leaves taken out, in the order
/// they were: what the leaves' operands are put back into.
enum Shape {
    And(Vec<Shape>),
    Or(Vec<Shape>),
    Not(Box<Shape>),
    /// A leaf's key in the tree (`contains`, `exists`, `cmp`, `elements`)
    /// and, for `cmp`, its bound's.
    Leaf(&'static str, Option<&'static str>),
}

impl Shape {
    /// The shape of `node`, its leaves pushed to `leaves` in order.
    fn of(node: Node, leaves: &mut Vec<Input>) -> Result<Self, Error> {
        Ok(match node {
            Node::And(children) => Shape::And(
                children
                    .into_iter()
                    .map(|c| Self::of(c, leaves))
                    .collect::<Result<_, _>>()?,
            ),
            Node::Or(children) => Shape::Or(
                children
                    .into_iter()
                    .map(|c| Self::of(c, leaves))
                    .collect::<Result<_, _>>()?,
            ),
            Node::Not(child) => Shape::Not(Box::new(Self::of(*child, leaves)?)),
            Node::Leaf(input) => {
                let shape = match &input {
                    Input::EqAt(..) => Shape::Leaf("contains", None),
                    Input::Selector(_) => Shape::Leaf("exists", None),
                    Input::Ordering(Compare::Lt, ..) => Shape::Leaf("cmp", Some("lt")),
                    Input::Ordering(Compare::Lte, ..) => Shape::Leaf("cmp", Some("lte")),
                    Input::Ordering(Compare::Gt, ..) => Shape::Leaf("cmp", Some("gt")),
                    Input::Ordering(Compare::Gte, ..) => Shape::Leaf("cmp", Some("gte")),
                    Input::Elements(..) => Shape::Leaf("elements", None),
                    _ => return Err(Error::Internal),
                };
                leaves.push(input);
                shape
            }
        })
    }

    /// The tree, each leaf's operand taken from `operands` in order: the
    /// `eql_v4.query_json_predicate` operand.
    fn fill(self, operands: &mut std::vec::IntoIter<Value>) -> Result<Value, crate::Error> {
        let missing = || crate::Error::Other("a compiled predicate lost a leaf".into());
        let list = |shapes: Vec<Shape>, operands: &mut std::vec::IntoIter<Value>| {
            shapes
                .into_iter()
                .map(|shape| shape.fill(operands))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(match self {
            Shape::And(children) => serde_json::json!({ "and": list(children, operands)? }),
            Shape::Or(children) => serde_json::json!({ "or": list(children, operands)? }),
            Shape::Not(child) => serde_json::json!({ "not": child.fill(operands)? }),
            Shape::Leaf(key, None) => {
                serde_json::json!({ key: operands.next().ok_or_else(missing)? })
            }
            Shape::Leaf(key, Some(bound)) => {
                serde_json::json!({ key: { bound: operands.next().ok_or_else(missing)? } })
            }
        })
    }
}

/// A leaf's operand as JSON: the EQL value's, or a selector's text.
fn operand_value(operand: Derived) -> Result<Value, crate::Error> {
    let json = |value: Result<Value, serde_json::Error>| {
        value.map_err(|error| crate::Error::Other(Box::new(error)))
    };
    match operand {
        Derived::Query(query) => json(serde_json::to_value(&query)),
        Derived::Leaf(leaf) => json(serde_json::to_value(&leaf)),
        Derived::Elements(elements) => json(serde_json::to_value(&elements)),
        Derived::Selector(selector) => Ok(Value::String(selector.to_string())),
        _ => Err(crate::Error::Other(
            "a predicate leaf derives one operand".into(),
        )),
    }
}

/// Derive a compiled predicate's operand: each leaf by its own operator's
/// derivation ([`derive_input`]), all in one pending, put back into the
/// tree.
pub(crate) fn derive<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    under: &Under<'_>,
    options: &JsonOptions,
    node: Node,
) -> Result<Pending<'a, JsonPredicateQuery, K>, Error> {
    let mut leaves = Vec::new();
    let shape = Shape::of(node, &mut leaves)?;
    let operands = leaves
        .into_iter()
        .map(|input| derive_input(keyset, under, options, input).map(|p| p.try_map(operand_value)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Pending::all(keyset, operands).try_map(move |operands| {
        shape
            .fill(&mut operands.into_iter())
            .map(JsonPredicateQuery)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::json::MAX_DEPTH;
    use crate::sem::TermError;
    use stack_encrypt_jsonpath::predicate::MAX_NESTING;

    use serde_json::json;

    /// A field ordering `$.age`, `$.name` and every contact's `calls` and
    /// `relationship`.
    fn options() -> JsonOptions {
        JsonOptions::new()
            .ordering([
                "$.age",
                "$.name",
                "$.contacts[*].calls",
                "$.contacts[*].relationship",
            ])
            .unwrap()
    }

    fn compiled(text: &str, vars: Value) -> Result<Node, Error> {
        compile(text, &vars, &options(), 4)
    }

    /// A compiled tree written out: each leaf its operator and its input.
    fn written(node: &Node) -> String {
        let list = |children: &[Node]| children.iter().map(written).collect::<Vec<_>>().join(", ");
        match node {
            Node::And(children) => format!("and({})", list(children)),
            Node::Or(children) => format!("or({})", list(children)),
            Node::Not(child) => format!("not({})", written(child)),
            Node::Leaf(input @ (Input::EqAt(path, value) | Input::Ordering(_, path, value))) => {
                format!("{}({path}, {})", input.name(), value.0)
            }
            Node::Leaf(input @ Input::Selector(path)) => format!("{}({path})", input.name()),
            Node::Leaf(input @ Input::Elements(bound, predicates)) => {
                let members: Vec<String> = predicates
                    .iter()
                    .map(|p| match &p.bounds {
                        Bounds::One(compare, value) => {
                            format!("{} {compare:?} {}", p.path, value.0)
                        }
                        Bounds::Between(low, high) => {
                            format!("{} in {}..{}", p.path, low.0, high.0)
                        }
                    })
                    .collect();
                format!("{}({bound}, [{}])", input.name(), members.join("; "))
            }
            Node::Leaf(input) => input.name().to_owned(),
        }
    }

    fn compiles_to(text: &str, vars: Value, want: &str) {
        let node = compiled(text, vars).unwrap_or_else(|error| panic!("{text}: {error}"));
        assert_eq!(written(&node), want, "{text}");
    }

    /// The refusal `text` meets: its reason, construct and offset.
    fn refusal(text: &str, vars: Value) -> (Reason, &'static str, usize) {
        match compiled(text, vars) {
            Err(Error::Predicate {
                reason,
                construct,
                at,
                ..
            }) => (reason, construct, at),
            Err(other) => panic!("{text}: not a predicate refusal: {other:?}"),
            Ok(node) => panic!("{text}: compiled to {}", written(&node)),
        }
    }

    mod given_the_grammar_it_reads {
        use super::*;

        /// Each comparison compiles onto the operators whose operands
        /// answer it as jsonpath does: `==` containment; `!=` a node that is
        /// not the value; an ordering a node, not null, whose leaf compares;
        /// and at a wildcard, an element's field.
        #[test]
        fn each_comparison_compiles_onto_its_operators() {
            for (text, want) in [
                (r#"$.name == "Ann""#, r#"eq_at($.name, "Ann")"#),
                ("$.age == 3", "eq_at($.age, 3)"),
                ("$.ok == true", "eq_at($.ok, true)"),
                ("$.gone == null", "eq_at($.gone, null)"),
                ("$.age != 3", "and(selector($.age), not(eq_at($.age, 3)))"),
                (
                    "$.age != null",
                    "and(selector($.age), not(eq_at($.age, null)))",
                ),
                ("$.age < 3", "and(selector($.age), lt_at($.age, 3))"),
                ("$.age <= 3", "and(selector($.age), lte_at($.age, 3))"),
                ("$.age > 3", "and(selector($.age), gt_at($.age, 3))"),
                ("$.age >= 3", "and(selector($.age), gte_at($.age, 3))"),
                ("$.tags[*] == \"x\"", r#"eq_at($.tags[*], "x")"#),
                (
                    "$.contacts[*].calls > 5",
                    "element_match(4, [$.contacts[*].calls Gt 5])",
                ),
                ("exists($.a.b)", "selector($.a.b)"),
                ("exists($.tags[*])", "selector($.tags[*])"),
            ] {
                compiles_to(text, json!({}), want);
            }
        }

        /// A value on the left is the comparison turned round, `<>` is
        /// `!=`, and a variable is its value in `vars`, of any JSON type a
        /// comparison takes.
        #[test]
        fn operands_are_read_in_either_order_and_by_variable() {
            for (text, want) in [
                ("3 < $.age", "and(selector($.age), gt_at($.age, 3))"),
                ("3 >= $.age", "and(selector($.age), lte_at($.age, 3))"),
                ("3 == $.age", "eq_at($.age, 3)"),
                ("$.age <> 3", "and(selector($.age), not(eq_at($.age, 3)))"),
                ("$.name == $who", r#"eq_at($.name, "Ann")"#),
                (r#"$.name == $"who""#, r#"eq_at($.name, "Ann")"#),
                ("$.age < $n", "and(selector($.age), lt_at($.age, 7))"),
                ("$.ok == $yes", "eq_at($.ok, true)"),
                ("$.gone == $nothing", "eq_at($.gone, null)"),
            ] {
                compiles_to(
                    text,
                    json!({"who": "Ann", "n": 7, "yes": true, "nothing": null}),
                    want,
                );
            }
        }

        /// Paths read as PostgreSQL reads them: quoted keys with JSON's
        /// escapes, keys that are words of the grammar, and space between
        /// steps; and literals as JSON reads them.
        #[test]
        fn paths_and_literals_read_as_postgres_reads_them() {
            for (text, want) in [
                (r#"$."first name" == 1"#, "eq_at($.first name, 1)"),
                (r#"$.  "a b".c == 1"#, "eq_at($.a b.c, 1)"),
                (r#"$."a\"b" == 1"#, r#"eq_at($["a\"b"], 1)"#),
                (r#"$."a" == 1"#, "eq_at($.a, 1)"),
                ("$.exists == 1", "eq_at($.exists, 1)"),
                ("$.size == 1", "eq_at($.size, 1)"),
                ("$.true == 1", "eq_at($.true, 1)"),
                ("$.é == 1", "eq_at($.é, 1)"),
                ("$ . a [ * ] . b == 1", "eq_at($.a[*].b, 1)"),
                ("  $.a==1  ", "eq_at($.a, 1)"),
                ("$.a == 1 /* why */", "eq_at($.a, 1)"),
                ("$.a == -1.5e3", "eq_at($.a, -1500.0)"),
                ("$.a == 0", "eq_at($.a, 0)"),
                ("$.a == 1.25", "eq_at($.a, 1.25)"),
                ("$.a == 10.125E+2", "eq_at($.a, 1012.5)"),
                ("$.a == 2e-1", "eq_at($.a, 0.2)"),
                (r#"$.a == "x\ty""#, r#"eq_at($.a, "x\ty")"#),
                ("$ == 1", "eq_at($, 1)"),
            ] {
                compiles_to(text, json!({}), want);
            }
        }

        /// `&&` binds tighter than `||`, parentheses group, `!` takes a
        /// group or `exists`, and the tree is flattened: an `and` in an
        /// `and` lifted, a repeated child dropped, `not` of `not` removed.
        #[test]
        fn the_boolean_structure_is_kept_and_flattened() {
            for (text, want) in [
                (
                    "$.a == 1 && $.b == 2 || $.c == 3",
                    "or(and(eq_at($.a, 1), eq_at($.b, 2)), eq_at($.c, 3))",
                ),
                (
                    "$.a == 1 && ($.b == 2 || $.c == 3)",
                    "and(eq_at($.a, 1), or(eq_at($.b, 2), eq_at($.c, 3)))",
                ),
                ("!($.a == 1)", "not(eq_at($.a, 1))"),
                ("! exists($.a)", "not(selector($.a))"),
                ("!(!($.a == 1))", "eq_at($.a, 1)"),
                ("((($.a == 1)))", "eq_at($.a, 1)"),
                (
                    "$.a == 1 && ($.b == 2 && $.c == 3)",
                    "and(eq_at($.a, 1), eq_at($.b, 2), eq_at($.c, 3))",
                ),
                (
                    "$.a == 1 || ($.b == 2 || $.c == 3)",
                    "or(eq_at($.a, 1), eq_at($.b, 2), eq_at($.c, 3))",
                ),
                ("$.a == 1 || $.a == 1", "eq_at($.a, 1)"),
                ("$.a == 1 && $.a == 1", "eq_at($.a, 1)"),
                (
                    "$.age > 1 && $.age < 9",
                    "and(selector($.age), gt_at($.age, 1), lt_at($.age, 9))",
                ),
                (
                    "EXISTS($.a) && Exists($.b)",
                    "and(selector($.a), selector($.b))",
                ),
            ] {
                compiles_to(text, json!({}), want);
            }
        }

        /// An ordering at one node carries the `null` needle only under an
        /// odd number of `!`, where it changes which rows match; elsewhere
        /// the selector and the ordering pick jsonpath's rows without it.
        #[test]
        fn an_ordering_sends_the_null_needle_only_under_an_odd_number_of_negations() {
            let needle = "not(eq_at($.age, null))";
            for (text, want) in [
                ("$.age < 3", "and(selector($.age), lt_at($.age, 3))"),
                (
                    "!($.age < 3)",
                    "not(and(selector($.age), not(eq_at($.age, null)), lt_at($.age, 3)))",
                ),
                ("!(!($.age < 3))", "and(selector($.age), lt_at($.age, 3))"),
                (
                    "!($.b == 1 || $.age >= 3)",
                    "not(or(eq_at($.b, 1), and(selector($.age), not(eq_at($.age, null)), gte_at($.age, 3))))",
                ),
                (
                    "!(!($.age > 3) && $.b == 1)",
                    "not(and(not(and(selector($.age), gt_at($.age, 3))), eq_at($.b, 1)))",
                ),
                (
                    "$.b == 1 && !($.age <= 3) || $.age > 9",
                    "or(and(eq_at($.b, 1), not(and(selector($.age), not(eq_at($.age, null)), lte_at($.age, 3)))), and(selector($.age), gt_at($.age, 9)))",
                ),
            ] {
                compiles_to(text, json!({}), want);
            }
            // A filter's conditions and an ordering at a wildcard are
            // element leaves, which carry no needle under any `!`.
            for text in [
                "!($.contacts[*].calls > 5)",
                "!(exists($.contacts[*] ? (@.calls > 5 && @.calls < 9)))",
            ] {
                let tree = written(&compiled(text, json!({})).unwrap());
                assert!(tree.starts_with("not(element_match("), "{text}: {tree}");
                assert!(!tree.contains(needle), "{text}: {tree}");
            }
        }

        /// A compiled tree prints its structure and operators, never the
        /// values or paths it holds.
        #[test]
        fn a_compiled_tree_prints_no_value() {
            let node = compiled(
                r#"!($."zq-secret" == "zq-secret") || exists($.age)"#,
                json!({}),
            )
            .unwrap();
            let shown = format!("{node:?}");
            assert_eq!(shown, "Or([Not(Leaf(EqAt)), Leaf(Selector)])");
        }

        /// `exists(path ? (…))`: one equality is containment at its field,
        /// exact; anything else is `element_match`, every condition on one
        /// element, read to the input's bound.
        #[test]
        fn a_filter_compiles_to_containment_or_an_element_match() {
            for (text, want) in [
                (
                    "exists($.contacts[*] ? (@.relationship == $r))",
                    r#"eq_at($.contacts[*].relationship, "Sibling")"#,
                ),
                (
                    "exists($.tags[*] ? (@ == $r))",
                    r#"eq_at($.tags[*], "Sibling")"#,
                ),
                ("exists($.tags[*] ? (1 == @))", "eq_at($.tags[*], 1)"),
                (
                    "exists($.contacts[*] ? (@.relationship == $r && @.calls > 5))",
                    r#"element_match(4, [$.contacts[*].relationship Eq "Sibling"; $.contacts[*].calls Gt 5])"#,
                ),
                (
                    "exists($.contacts[*] ? ((@.calls >= 1) && (@.calls < 9)))",
                    "element_match(4, [$.contacts[*].calls Gte 1; $.contacts[*].calls Lt 9])",
                ),
                (
                    "exists($.contacts[*] ? (@.calls < 2))",
                    "element_match(4, [$.contacts[*].calls Lt 2])",
                ),
            ] {
                compiles_to(text, json!({"r": "Sibling"}), want);
            }
        }
    }

    mod given_text_it_refuses {
        use super::*;

        use Reason::{
            JsonPathNoWildcard, JsonPathPosition, JsonPathWildcard,
            JsonPredicateNotEqualAtWildcard, JsonPredicateSyntax, JsonPredicateTooDeep,
            JsonPredicateUnknownVariable, JsonPredicateUnsupported, JsonPredicateValueType,
            JsonSyntax,
        };

        /// Each construct the index cannot answer is refused by name, at
        /// the byte in the caller's text where it starts.
        #[test]
        fn names_each_unsupported_construct_at_its_offset() {
            for (text, construct, at) in [
                ("strict $.a == 1", construct::MODE, 0),
                ("STRICT $.a == 1", construct::MODE, 0),
                ("$.a == Lax", construct::MODE, 7),
                (r#"$.a LIKE_REGEX "x""#, construct::LIKE_REGEX, 4),
                (r#"$.a Starts with "x""#, construct::STARTS_WITH, 4),
                ("$.a IS unknown", construct::IS_UNKNOWN, 4),
                ("$.a[LAST] == 1", construct::LAST, 3),
                ("$.a == LAST", construct::LAST, 7),
                (r#"exists($.a like_regex "x")"#, construct::LIKE_REGEX, 11),
                ("exists($.a + 1)", construct::ARITHMETIC, 11),
                (
                    "exists($.a[*] ? (@ == 1) starts with \"x\")",
                    construct::STARTS_WITH,
                    25,
                ),
                ("  lax $.a == 1", construct::MODE, 2),
                ("$.a + 1 == 2", construct::ARITHMETIC, 4),
                ("$.a == 1 - 2", construct::ARITHMETIC, 9),
                ("$.a == +1", construct::ARITHMETIC, 7),
                (r#"$.a like_regex "x""#, construct::LIKE_REGEX, 4),
                (r#"$.a starts with "x""#, construct::STARTS_WITH, 4),
                ("$.a is unknown", construct::IS_UNKNOWN, 4),
                ("$.a.size() == 1", construct::METHOD, 3),
                ("$.a.type () == 1", construct::METHOD, 3),
                ("$.* == 1", construct::ANY_MEMBER, 1),
                ("$.** == 1", construct::ANY_DEPTH, 1),
                ("$.a[1 to 2] == 1", construct::SLICE, 3),
                ("$.a[1, 2] == 1", construct::SLICE, 3),
                ("$.a[last] == 1", construct::LAST, 3),
                ("$.a == last", construct::LAST, 7),
                ("$.a == lax", construct::MODE, 7),
                ("$.a[$i] == 1", construct::SUBSCRIPT, 3),
                ("@ == 1", construct::AT_OUTSIDE, 0),
                ("$.a == $.b", construct::TWO_PATHS, 4),
                ("1 == 1", construct::TWO_VALUES, 2),
                ("$x == $y", construct::TWO_VALUES, 3),
                ("$.a", construct::ALONE, 3),
                ("$.a && $.b == 1", construct::ALONE, 4),
                ("true", construct::ALONE, 4),
                ("$.a[*] ? (@ == 1) == 1", construct::FILTER_OUTSIDE, 7),
                ("exists($.a[*] ? (@ == 1).b)", construct::AFTER_FILTER, 24),
                (
                    "exists($.a[*] ? (@ == 1) ? (@ == 2))",
                    construct::FILTER_OUTSIDE,
                    24,
                ),
                ("exists($.a == 1)", construct::IN_EXISTS, 7),
                ("exists(@)", construct::AT_OUTSIDE, 7),
                (
                    "exists($.a[*] ? (@.b == 1 || @.c == 2))",
                    construct::OR_IN_FILTER,
                    26,
                ),
                (
                    "exists($.a[*] ? (!(@.b == 1)))",
                    construct::NOT_IN_FILTER,
                    17,
                ),
                (
                    "exists($.a[*] ? (@.b != 1))",
                    construct::NOT_EQUAL_IN_FILTER,
                    21,
                ),
                (
                    "exists($.a[*] ? (exists(@.b)))",
                    construct::EXISTS_IN_FILTER,
                    17,
                ),
                (
                    "exists($.a[*] ? ($.b == 1))",
                    construct::DOLLAR_IN_FILTER,
                    17,
                ),
                ("$.v == $x.y", construct::VARIABLE_PATH, 9),
                ("$.tags[*] < 1", construct::ELEMENTS_THEMSELVES, 10),
                (
                    "exists($.contacts[*] ? (@ > 1 && @.calls < 2))",
                    construct::ELEMENTS_THEMSELVES,
                    24,
                ),
                (
                    "exists($.contacts[*] ? (@ == 1 && @.calls < 2))",
                    construct::WHOLE_ELEMENT,
                    24,
                ),
            ] {
                assert_eq!(
                    refusal(text, json!({"x": 1, "y": 2})),
                    (JsonPredicateUnsupported, construct, at),
                    "{text}"
                );
            }
        }

        /// Text that is not a predicate is refused where reading stops.
        #[test]
        fn refuses_text_that_is_not_a_predicate_where_reading_stops() {
            for (text, construct, at) in [
                ("", construct::TEXT, 0),
                ("$.a == 1 &&", construct::TEXT, 11),
                ("$.a = 1", construct::TEXT, 4),
                ("$.a === 1", construct::TEXT, 6),
                ("$.a > 1 > 2", construct::TRAILING, 8),
                ("$.a == 1 2", construct::TRAILING, 9),
                ("($.a == 1) is unknown", construct::TRAILING, 11),
                ("!$.a == 1", construct::TEXT, 1),
                ("!!($.a == 1)", construct::TEXT, 1),
                ("($.a == 1", construct::TEXT, 9),
                ("$.a == 01", construct::NUMBER, 7),
                ("$.a == 1.", construct::NUMBER, 7),
                ("$.a == 1e", construct::NUMBER, 7),
                ("$.a == .5", construct::TEXT, 7),
                ("$.a == 'x'", construct::TEXT, 7),
                (r#"$.a == "x"#, construct::STRING, 7),
                (r#"$."a == 1"#, construct::STRING, 2),
                ("$.a == TRUE", construct::TEXT, 7),
                ("$.1a == 1", construct::TEXT, 2),
                ("$. == 1", construct::TEXT, 3),
                ("$.a == 1 /* open", construct::TEXT, 9),
                ("exists $.a", construct::TEXT, 7),
                ("$.a == $1", construct::TEXT, 8),
            ] {
                assert_eq!(
                    refusal(text, json!({})),
                    (JsonPredicateSyntax, construct, at),
                    "{text}"
                );
            }
        }

        /// A value is refused at its offset when no variable holds it, its
        /// type is not one the comparison takes, or its text is not JSON.
        #[test]
        fn refuses_a_value_the_comparison_cannot_take_at_its_offset() {
            let vars = json!({"doc": {"a": 1}, "list": [1], "n": 1, "flag": true, "none": null});
            for (text, reason, at) in [
                ("$.a == $missing", JsonPredicateUnknownVariable, 7),
                ("$missing < $.age", JsonPredicateUnknownVariable, 0),
                ("$.a == $doc", JsonPredicateValueType, 7),
                ("$.a != $list", JsonPredicateValueType, 7),
                ("$.age < $doc", JsonPredicateValueType, 8),
                ("$list <= $.age", JsonPredicateValueType, 0),
                ("$.age < true", JsonPredicateValueType, 8),
                ("$.age < $flag", JsonPredicateValueType, 8),
                ("$.age >= null", JsonPredicateValueType, 9),
                ("$.age >= $none", JsonPredicateValueType, 9),
                (
                    "exists($.contacts[*] ? (@.calls == $n && @.relationship == $flag))",
                    JsonPredicateValueType,
                    59,
                ),
                (r#"$.a == "\x41""#, JsonPredicateSyntax, 7),
                (r#"$.a == 1e999"#, JsonSyntax, 7),
            ] {
                let (got, _, offset) = refusal(text, vars.clone());
                assert_eq!((got, offset), (reason, at), "{text}");
            }
        }

        /// What the index's paths cannot name: a position, `!=` at a
        /// wildcard, a filter on a path with no wildcard, a wildcard in a
        /// filter's member, and nesting or paths past the limits.
        #[test]
        fn refuses_paths_the_index_cannot_name() {
            let deep = format!(
                "{} $.a == 1{}",
                "(".repeat(MAX_NESTING + 1),
                ")".repeat(MAX_NESTING + 1)
            );
            let long = format!("$.{} == 1", vec!["a"; MAX_DEPTH + 1].join("."));
            for (text, want) in [
                ("$.a[2] == 1", (JsonPathPosition, construct::POSITION, 3)),
                (
                    "exists($.a[ 0 ])",
                    (JsonPathPosition, construct::POSITION, 10),
                ),
                (
                    "$.a[*] != 1",
                    (JsonPredicateNotEqualAtWildcard, construct::NOT_EQUAL, 7),
                ),
                (
                    "$.a[*].b != null",
                    (JsonPredicateNotEqualAtWildcard, construct::NOT_EQUAL, 9),
                ),
                (
                    "exists($.a ? (@ == 1))",
                    (JsonPathNoWildcard, construct::FILTER_WILDCARD, 7),
                ),
                (
                    "exists($.a[*] ? (@.b[*] == 1))",
                    (JsonPathWildcard, construct::MEMBER_WILDCARD, 17),
                ),
                (
                    deep.as_str(),
                    (JsonPredicateTooDeep, construct::NESTING, MAX_NESTING + 1),
                ),
                (long.as_str(), (JsonPredicateTooDeep, construct::NESTING, 0)),
            ] {
                assert_eq!(refusal(text, json!({})), want, "{text}");
            }
            let at_limit = format!(
                "{}$.a == 1{}",
                "(".repeat(MAX_NESTING),
                ")".repeat(MAX_NESTING)
            );
            assert!(compiled(&at_limit, json!({})).is_ok(), "the limit is read");
            // A filter's equality is at the base and the member joined, as
            // deep as a document at most.
            let member =
                |steps: usize| format!("exists($.a[*] ? (@.{} == 1))", vec!["b"; steps].join("."));
            assert!(
                compiled(&member(MAX_DEPTH - 2), json!({})).is_ok(),
                "a filter's full path as deep as a document"
            );
            assert_eq!(
                refusal(&member(MAX_DEPTH - 1), json!({})),
                (JsonPredicateTooDeep, construct::NESTING, 7),
                "one equality: a filter's full path deeper than a document"
            );
            let members = |steps: usize| {
                format!(
                    "exists($.contacts[*] ? (@.calls > 1 && @.{} < 2))",
                    vec!["b"; steps].join(".")
                )
            };
            assert_eq!(
                refusal(&members(MAX_DEPTH - 1), json!({})),
                (JsonPredicateTooDeep, construct::NESTING, 7),
                "two conditions: a member's full path deeper than a document"
            );
            assert!(
                matches!(
                    compiled(&members(MAX_DEPTH - 2), json!({})),
                    Err(Error::Cipher(crate::Error::Term(
                        TermError::JsonPathNotOrdered
                    )))
                ),
                "as deep as a document is read, and refused only as unordered"
            );
            let deepest = format!("$.{} == 1", vec!["a"; MAX_DEPTH].join("."));
            assert!(
                compiled(&deepest, json!({})).is_ok(),
                "a path as deep as a document"
            );
            // A step past a document's depth is refused before it is read.
            let past = format!("$.{}.** == 1", vec!["a"; MAX_DEPTH].join("."));
            assert_eq!(
                refusal(&past, json!({})),
                (JsonPredicateTooDeep, construct::NESTING, 0),
                "the step past the depth is not read"
            );
            // Nesting is depth, not count: siblings past the limit, each
            // in its own group or under its own `!` or `exists`, are read.
            for sibling in ["($.a == 1)", "!($.a == 1)", "exists($.a)"] {
                let wide = vec![sibling; MAX_NESTING + 1].join(" && ");
                assert!(compiled(&wide, json!({})).is_ok(), "{sibling} side by side");
            }
            let filters =
                vec!["exists($.contacts[*] ? ((@.calls > 1)))"; MAX_NESTING + 1].join(" || ");
            assert!(
                compiled(&filters, json!({})).is_ok(),
                "filters side by side"
            );
        }

        /// The index's own refusals of the leaves' inputs come through as
        /// the operators give them: an ordering at a path the field does not
        /// order, here or at an element's field.
        #[test]
        fn refuses_an_ordering_at_a_path_the_field_does_not_order() {
            for text in [
                "$.height > 1",
                "$.contacts[*].note > 1",
                "exists($.contacts[*] ? (@.note > 1 && @.calls < 2))",
            ] {
                assert!(
                    matches!(
                        compiled(text, json!({})),
                        Err(Error::Cipher(crate::Error::Term(
                            TermError::JsonPathNotOrdered
                        )))
                    ),
                    "{text}"
                );
            }
        }

        /// A refusal carries the construct and the offset, never text from
        /// the predicate.
        #[test]
        fn a_refusal_quotes_no_text_of_the_predicate() {
            let secret = "zq-secret-key-name";
            for text in [
                format!(r#"$."{secret}" like_regex "x""#),
                format!(r#"$.{secret} == "{secret}" + 1"#),
                format!(r#"$.{secret} == ${secret}"#),
                format!(r#"$.{secret} == "{secret}" {secret}"#),
            ] {
                let error = compiled(&text, json!({})).unwrap_err();
                let shown = format!("{error} {:?}", crate::ErrorPayload::payload(&error));
                assert!(!shown.contains(secret), "{shown}");
            }
        }
    }
}
