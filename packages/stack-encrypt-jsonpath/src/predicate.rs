//! The SQL/JSON path predicates the JSON index can answer: their grammar,
//! read from text into an [`Expression`].
//!
//! The text is PostgreSQL's SQL/JSON path language, as `jsonb_path_match`
//! takes it ([SQL/JSON path language](https://www.postgresql.org/docs/current/functions-json.html#FUNCTIONS-SQLJSON-PATH)),
//! restricted to predicates the JSON index's terms can answer:
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
//! `stack-encrypt` compiles an [`Expression`] onto the inputs of its JSON
//! operators when a query is encrypted, and `stack-encrypt-derive`'s
//! `predicate!` reads the same text when a program compiles. Both read it
//! with [`parse`], so the two cannot disagree about what a predicate says.
//! The rules that refuse a construct the index cannot answer, and that
//! depend on neither the variables' values nor the field's options, are
//! here too ([`Comparison::refuse_not_equal_at_wildcard`],
//! [`PathAt::element_member`], [`check_filter`],
//! [`Comparison::check_filter_condition`]), so each is written once.
//!
//! A refusal names a construct in the grammar's words ([`construct`]) and
//! an offset, never a slice of the text: a key name or a value in it can be
//! customer data. The tree holds offsets into the text, the key names in
//! [`JsonPath`]s, which wipe them, and a variable's name in storage that is
//! wiped.
//!
//! ```
//! use stack_encrypt_jsonpath::predicate::{self, Expression, Operator};
//!
//! let Expression::Compare(comparison) = predicate::parse("$.age >= $min")? else {
//!     unreachable!("one comparison")
//! };
//! assert_eq!(comparison.path.path.to_string(), "$.age");
//! assert_eq!(comparison.operator, Operator::GreaterOrEqual);
//! assert_eq!(comparison.value.variable(), Some("min"));
//!
//! let refused = predicate::parse("$.age like_regex \"^4\"").unwrap_err();
//! assert_eq!(refused.construct, predicate::construct::LIKE_REGEX);
//! assert_eq!(refused.at, 6);
//! # Ok::<(), predicate::PredicateError>(())
//! ```

use zeroize::Zeroizing;

use crate::json_string::{string_end, string_text};
use crate::{JsonPath, Segment, MAX_DEPTH};

/// How deeply a predicate may nest parentheses, `!` and `exists`. The
/// parser descends once per level, so the bound keeps a hostile predicate
/// from overflowing the stack; the SQL evaluates the compiled tree by
/// recursion too.
pub const MAX_NESTING: usize = 32;

/// The constructs a refusal names, in the grammar's own words.
pub mod construct {
    /// Text the grammar does not read.
    pub const TEXT: &str = "text the grammar does not read";
    /// Text after a whole predicate.
    pub const TRAILING: &str = "text after the predicate";
    /// A string literal that is not JSON string text.
    pub const STRING: &str = "a string literal";
    /// A numeric literal that is not JSON number text.
    pub const NUMBER: &str = "a numeric literal";
    /// `strict` or `lax`.
    pub const MODE: &str = "a mode (`strict`, `lax`)";
    /// `+`, `-`, `*`, `/` or `%`.
    pub const ARITHMETIC: &str = "arithmetic (`+`, `-`, `*`, `/`, `%`)";
    /// `like_regex`.
    pub const LIKE_REGEX: &str = "`like_regex`";
    /// `starts with`.
    pub const STARTS_WITH: &str = "`starts with`";
    /// `is unknown`.
    pub const IS_UNKNOWN: &str = "`is unknown`";
    /// A method call on a path.
    pub const METHOD: &str = "a method (`.name()`)";
    /// Every member of an object.
    pub const ANY_MEMBER: &str = "`.*`";
    /// Every node at any depth.
    pub const ANY_DEPTH: &str = "`.**`";
    /// An array slice or a list of positions.
    pub const SLICE: &str = "an array slice or list (`[a to b]`, `[a, b]`)";
    /// `last`.
    pub const LAST: &str = "`last`";
    /// A subscript the grammar reads and the index cannot answer.
    pub const SUBSCRIPT: &str = "a subscript other than `[*]`";
    /// One array element, by position.
    pub const POSITION: &str = "a position (`[2]`)";
    /// `@` where there is no current element.
    pub const AT_OUTSIDE: &str = "`@` outside a filter";
    /// A path from the root inside a filter.
    pub const DOLLAR_IN_FILTER: &str = "a `$` path in a filter";
    /// A step after a variable.
    pub const VARIABLE_PATH: &str = "an accessor on a variable";
    /// A comparison with a path on both sides.
    pub const TWO_PATHS: &str = "a comparison of two paths";
    /// A comparison with a value on both sides.
    pub const TWO_VALUES: &str = "a comparison of two values";
    /// A path or a value standing alone.
    pub const ALONE: &str = "an operand with no comparison";
    /// A filter anywhere but inside `exists`.
    pub const FILTER_OUTSIDE: &str = "a filter outside `exists`";
    /// A step after a filter.
    pub const AFTER_FILTER: &str = "an accessor after a filter";
    /// A comparison inside `exists`.
    pub const IN_EXISTS: &str = "a comparison inside `exists`";
    /// `||` inside a filter.
    pub const OR_IN_FILTER: &str = "`||` in a filter";
    /// `!` inside a filter.
    pub const NOT_IN_FILTER: &str = "`!` in a filter";
    /// `!=` inside a filter.
    pub const NOT_EQUAL_IN_FILTER: &str = "`!=` in a filter";
    /// `exists` inside a filter.
    pub const EXISTS_IN_FILTER: &str = "`exists` in a filter";
    /// An ordering of the elements of an array, rather than of their
    /// members.
    pub const ELEMENTS_THEMSELVES: &str = "an ordering of an array's elements themselves";
    /// A condition on `@` itself beside another condition.
    pub const WHOLE_ELEMENT: &str = "`@` beside another condition";
    /// A filter on a path that names no array's elements.
    pub const FILTER_WILDCARD: &str = "a filter on a path with no wildcard";
    /// A wildcard in the path a filter's condition names.
    pub const MEMBER_WILDCARD: &str = "a wildcard in a filter's member";
    /// `!=` at a path with a wildcard.
    pub const NOT_EQUAL: &str = "`!=` at a path with a wildcard";
    /// A value the comparison cannot take.
    pub const VALUE: &str = "a value";
    /// A variable.
    pub const VARIABLE: &str = "a variable";
    /// Nesting past the limits.
    pub const NESTING: &str = "nesting";
}

/// What kind of refusal a [`PredicateError`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PredicateErrorKind {
    /// The text is not predicate text.
    Syntax,
    /// The text uses a construct the index cannot answer.
    Unsupported,
    /// The text nests parentheses, `!` or `exists`, or a path, too deep.
    TooDeep,
    /// A path names an array position (`[2]`), which the index reads as
    /// the wildcard.
    Position,
    /// `!=` at a path with a wildcard: whether some element differs, which
    /// containment cannot say.
    NotEqualAtWildcard,
    /// A filter on a path with no wildcard: there are no elements to
    /// filter.
    FilterWithoutWildcard,
    /// A wildcard in a filter's member: a condition holds of one element's
    /// member, not of an array inside it.
    MemberWildcard,
}

/// Why a predicate is refused: the kind of refusal, the construct, and the
/// byte offset in the text where the construct starts. Never text from the
/// predicate, which can name customer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{construct} at byte {at}")]
pub struct PredicateError {
    /// The kind of refusal.
    pub kind: PredicateErrorKind,
    /// The construct refused, in the grammar's words: one of [`construct`].
    pub construct: &'static str,
    /// The byte offset in the text where the construct starts.
    pub at: usize,
}

impl PredicateError {
    fn syntax(construct: &'static str, at: usize) -> Self {
        Self {
            kind: PredicateErrorKind::Syntax,
            construct,
            at,
        }
    }

    fn unsupported(construct: &'static str, at: usize) -> Self {
        Self {
            kind: PredicateErrorKind::Unsupported,
            construct,
            at,
        }
    }

    fn too_deep(at: usize) -> Self {
        Self {
            kind: PredicateErrorKind::TooDeep,
            construct: construct::NESTING,
            at,
        }
    }
}

/// A comparison operator, as the text spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    /// `==`.
    Equal,
    /// `!=` or `<>`.
    NotEqual,
    /// `<`.
    Less,
    /// `<=`.
    LessOrEqual,
    /// `>`.
    Greater,
    /// `>=`.
    GreaterOrEqual,
}

impl Operator {
    /// The operator with its operands swapped: `1 < $.a` is `$.a > 1`.
    pub fn flipped(self) -> Self {
        match self {
            Operator::Less => Operator::Greater,
            Operator::LessOrEqual => Operator::GreaterOrEqual,
            Operator::Greater => Operator::Less,
            Operator::GreaterOrEqual => Operator::LessOrEqual,
            same => same,
        }
    }
}

/// A path in the text: `$` or `@` and the steps after it, and where it
/// starts.
#[derive(Debug)]
pub struct PathAt {
    /// The path. A path from `@` holds the steps after the current element.
    pub path: JsonPath,
    /// The byte offset of its `$` or `@`.
    pub at: usize,
}

/// A value in the text: a literal, by its bytes, or a variable, by name.
#[derive(Debug, PartialEq, Eq)]
pub enum ValueAt {
    /// `"…"`, a number, `true`, `false` or `null`: the literal's bytes,
    /// `start..end`, which are JSON text.
    Literal {
        /// The offset of its first byte.
        start: usize,
        /// The offset after its last byte.
        end: usize,
    },
    /// `$name` or `$"name"`.
    Variable {
        /// The name, decoded, wiped when it drops.
        name: Zeroizing<String>,
        /// The offset of its `$`.
        at: usize,
    },
}

/// What a literal is, by the JSON type its text writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteralKind {
    /// `"…"`.
    String,
    /// A number.
    Number,
    /// `true` or `false`.
    Boolean,
    /// `null`.
    Null,
}

impl ValueAt {
    /// The offset where the value starts.
    pub fn at(&self) -> usize {
        match self {
            ValueAt::Literal { start, .. } => *start,
            ValueAt::Variable { at, .. } => *at,
        }
    }

    /// The variable's name, for a variable.
    pub fn variable(&self) -> Option<&str> {
        match self {
            ValueAt::Variable { name, .. } => Some(name.as_str()),
            ValueAt::Literal { .. } => None,
        }
    }

    /// What a literal is, read from `text`, the predicate the value was
    /// parsed from; `None` for a variable. The parser reads a literal only
    /// when it starts as one of these.
    pub fn literal_kind(&self, text: &str) -> Option<LiteralKind> {
        let ValueAt::Literal { start, .. } = self else {
            return None;
        };
        Some(match text.as_bytes().get(*start) {
            Some(b'"') => LiteralKind::String,
            Some(b't' | b'f') => LiteralKind::Boolean,
            Some(b'n') => LiteralKind::Null,
            _ => LiteralKind::Number,
        })
    }

    /// The literal's text, read from `text`, the predicate the value was
    /// parsed from; `None` for a variable.
    pub fn literal_text<'t>(&self, text: &'t str) -> Option<&'t str> {
        match self {
            ValueAt::Literal { start, end } => text.get(*start..*end),
            ValueAt::Variable { .. } => None,
        }
    }
}

/// A comparison of a path with a value, the path on the left.
#[derive(Debug)]
pub struct Comparison {
    /// The path compared.
    pub path: PathAt,
    /// The operator, turned round if the text wrote the value first.
    pub operator: Operator,
    /// The value compared with.
    pub value: ValueAt,
    /// Where the operator is.
    pub at: usize,
}

impl Comparison {
    /// `!=` at a path with a wildcard is true when some element differs,
    /// which containment cannot say: refused at the operator.
    ///
    /// # Errors
    ///
    /// [`PredicateErrorKind::NotEqualAtWildcard`] for `!=` at a path with
    /// a wildcard.
    pub fn refuse_not_equal_at_wildcard(&self) -> Result<(), PredicateError> {
        if self.operator == Operator::NotEqual && !self.path.path.is_positional() {
            return Err(PredicateError {
                kind: PredicateErrorKind::NotEqualAtWildcard,
                construct: construct::NOT_EQUAL,
                at: self.at,
            });
        }
        Ok(())
    }

    /// One condition of a filter with more than one, which becomes one
    /// member of an element-scoped predicate: an ordering or an equality on
    /// a member below the element.
    ///
    /// # Errors
    ///
    /// [`PredicateErrorKind::Unsupported`] for `!=`, and for a condition on
    /// `@` itself, which names no member.
    pub fn check_filter_condition(&self) -> Result<(), PredicateError> {
        if self.operator == Operator::NotEqual {
            return Err(PredicateError::unsupported(
                construct::NOT_EQUAL_IN_FILTER,
                self.at,
            ));
        }
        if self.path.path.segments().is_empty() {
            let construct = if self.operator == Operator::Equal {
                construct::WHOLE_ELEMENT
            } else {
                construct::ELEMENTS_THEMSELVES
            };
            return Err(PredicateError::unsupported(construct, self.path.at));
        }
        Ok(())
    }
}

impl PathAt {
    /// The array and the member of an ordering at a path with a wildcard:
    /// the path up to its last wildcard, and the steps after it. `None`
    /// for a path with no wildcard, which names one node and no array.
    /// `operator_at` is where the ordering's operator is.
    ///
    /// # Errors
    ///
    /// [`PredicateErrorKind::Unsupported`] at the operator when no step
    /// follows the last wildcard: an ordering of the elements themselves.
    pub fn element_member(
        &self,
        operator_at: usize,
    ) -> Result<Option<(JsonPath, JsonPath)>, PredicateError> {
        let steps = self.path.segments();
        let Some(last) = steps
            .iter()
            .rposition(|segment| *segment == Segment::Wildcard)
        else {
            return Ok(None);
        };
        // Each half is copied straight into a path, which wipes its keys,
        // before anything can refuse.
        let (base, member) = steps.split_at(last + 1);
        let (base, member) = (
            JsonPath::from(base.to_vec()),
            JsonPath::from(member.to_vec()),
        );
        if member.segments().is_empty() {
            return Err(PredicateError::unsupported(
                construct::ELEMENTS_THEMSELVES,
                operator_at,
            ));
        }
        Ok(Some((base, member)))
    }
}

/// The checks of `exists(path ? (conditions))` that hold whatever the
/// conditions compare: the path names an array's elements, every condition
/// names a member below one element, and no member's full path is deeper
/// than a document.
///
/// # Errors
///
/// [`PredicateErrorKind::FilterWithoutWildcard`] at the path for a path
/// with no wildcard; [`PredicateErrorKind::TooDeep`] at the path for a
/// member whose full path is deeper than [`MAX_DEPTH`];
/// [`PredicateErrorKind::MemberWildcard`] at a condition's path for a
/// member with a wildcard.
pub fn check_filter(path: &PathAt, conditions: &[Comparison]) -> Result<(), PredicateError> {
    if path.path.is_positional() {
        return Err(PredicateError {
            kind: PredicateErrorKind::FilterWithoutWildcard,
            construct: construct::FILTER_WILDCARD,
            at: path.at,
        });
    }
    for condition in conditions {
        if path.path.segments().len() + condition.path.path.segments().len() > MAX_DEPTH {
            return Err(PredicateError::too_deep(path.at));
        }
        if !condition.path.path.is_positional() {
            return Err(PredicateError {
                kind: PredicateErrorKind::MemberWildcard,
                construct: construct::MEMBER_WILDCARD,
                at: condition.path.at,
            });
        }
    }
    Ok(())
}

/// The one condition of a filter that is a single equality, which is
/// containment at the condition's full path rather than an element-scoped
/// predicate.
pub fn single_equality(conditions: &[Comparison]) -> Option<&Comparison> {
    match conditions {
        [only] if only.operator == Operator::Equal => Some(only),
        _ => None,
    }
}

/// A predicate as the text writes it.
#[derive(Debug)]
pub enum Expression {
    /// Every term holds.
    And(Vec<Expression>),
    /// Some term holds.
    Or(Vec<Expression>),
    /// The term does not hold.
    Not(Box<Expression>),
    /// A path compared with a value.
    Compare(Comparison),
    /// `exists(path)`, or `exists(path ? (conditions))`, each condition a
    /// comparison of a path from `@`.
    Exists {
        /// The path whose node, or whose elements, exist.
        path: PathAt,
        /// The conditions one element satisfies together.
        filter: Option<Vec<Comparison>>,
    },
}

/// One side of a comparison.
#[derive(Debug)]
enum Side {
    /// A path from `$`.
    Root(PathAt),
    /// A path from `@`, inside a filter.
    Current(PathAt),
    Value(ValueAt),
}

/// The characters that end a name and are not a name's: what
/// PostgreSQL's jsonpath scanner reads as punctuation.
fn special(c: char) -> bool {
    c.is_whitespace() || "?%$.[]{}()|&!=<>@#,*:-+/\\\"'".contains(c)
}

/// A recursive descent over the text, holding the offset it has read to.
struct Parser<'t> {
    text: &'t str,
    pos: usize,
    depth: usize,
}

impl<'t> Parser<'t> {
    fn rest(&self) -> &'t str {
        &self.text[self.pos..]
    }

    /// Skip whitespace and `/* … */` comments.
    fn space(&mut self) -> Result<(), PredicateError> {
        loop {
            let rest = self.rest();
            let trimmed = rest.trim_start();
            self.pos += rest.len() - trimmed.len();
            if let Some(comment) = trimmed.strip_prefix("/*") {
                let Some(end) = comment.find("*/") else {
                    return Err(PredicateError::syntax(construct::TEXT, self.pos));
                };
                self.pos += 2 + end + 2;
            } else {
                return Ok(());
            }
        }
    }

    /// The next character after any space, unread.
    fn peek(&mut self) -> Result<Option<char>, PredicateError> {
        self.space()?;
        Ok(self.rest().chars().next())
    }

    /// Read `token` if it is next.
    fn eat(&mut self, token: &str) -> Result<bool, PredicateError> {
        self.space()?;
        if self.rest().starts_with(token) {
            self.pos += token.len();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn expect(&mut self, token: &str) -> Result<(), PredicateError> {
        if self.eat(token)? {
            Ok(())
        } else {
            Err(PredicateError::syntax(construct::TEXT, self.pos))
        }
    }

    /// The name at the cursor, unread: a run of characters that are not
    /// punctuation, not starting with a digit.
    fn word(&mut self) -> Result<Option<&'t str>, PredicateError> {
        self.space()?;
        let rest = self.rest();
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return Ok(None);
        }
        let end = rest.find(special).unwrap_or(rest.len());
        Ok((end > 0).then(|| &rest[..end]))
    }

    /// One more level of nesting, refused past [`MAX_NESTING`].
    fn descend(&mut self) -> Result<(), PredicateError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(PredicateError::too_deep(self.pos));
        }
        Ok(())
    }

    fn ascend(&mut self) {
        self.depth -= 1;
    }

    /// `or := and ('||' and)*`.
    fn or(&mut self) -> Result<Expression, PredicateError> {
        let mut terms = vec![self.and()?];
        while self.eat("||")? {
            terms.push(self.and()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expression::Or(terms)
        })
    }

    /// `and := unary ('&&' unary)*`.
    fn and(&mut self) -> Result<Expression, PredicateError> {
        let mut terms = vec![self.unary()?];
        while self.eat("&&")? {
            terms.push(self.unary()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expression::And(terms)
        })
    }

    /// `unary := '!' primary | primary`. As in PostgreSQL, `!` takes a
    /// parenthesised predicate or `exists`, not a bare comparison.
    fn unary(&mut self) -> Result<Expression, PredicateError> {
        self.space()?;
        if self.rest().starts_with('!') && !self.rest().starts_with("!=") {
            self.pos += 1;
            self.descend()?;
            let at = self.pos;
            let negated = match self.peek()? {
                Some('(') => self.primary()?,
                _ if self.keyword("exists")? => self.primary()?,
                _ => return Err(PredicateError::syntax(construct::TEXT, at)),
            };
            self.ascend();
            return Ok(Expression::Not(Box::new(negated)));
        }
        self.primary()
    }

    /// Whether the word at the cursor is `keyword`, in any case, as
    /// PostgreSQL reads `exists`.
    fn keyword(&mut self, keyword: &str) -> Result<bool, PredicateError> {
        Ok(self
            .word()?
            .is_some_and(|word| word.eq_ignore_ascii_case(keyword)))
    }

    /// `primary := '(' or ')' | 'exists' '(' path filter? ')' | comparison`.
    fn primary(&mut self) -> Result<Expression, PredicateError> {
        if self.eat("(")? {
            self.descend()?;
            let inner = self.or()?;
            self.expect(")")?;
            self.ascend();
            return Ok(inner);
        }
        if self.keyword("exists")? {
            self.pos += "exists".len();
            if self.eat("(")? {
                return self.exists();
            }
            return Err(PredicateError::syntax(construct::TEXT, self.pos));
        }
        let comparison = self.comparison(false)?;
        Ok(Expression::Compare(comparison))
    }

    /// The inside of `exists(…)`, the `(` read.
    fn exists(&mut self) -> Result<Expression, PredicateError> {
        self.descend()?;
        self.space()?;
        let at = self.pos;
        let path = match self.operand(false)? {
            Side::Root(path) => path,
            Side::Current(_) => return Err(PredicateError::unsupported(construct::AT_OUTSIDE, at)),
            Side::Value(_) => return Err(PredicateError::syntax(construct::TEXT, at)),
        };
        let filter = if self.eat("?")? {
            self.expect("(")?;
            self.descend()?;
            let conditions = self.conditions()?;
            self.expect(")")?;
            self.ascend();
            let at = self.pos;
            match self.peek()? {
                Some('.' | '[') => {
                    return Err(PredicateError::unsupported(construct::AFTER_FILTER, at))
                }
                Some('?') => {
                    return Err(PredicateError::unsupported(construct::FILTER_OUTSIDE, at))
                }
                _ => {}
            }
            Some(conditions)
        } else {
            None
        };
        if let Some(refusal) = self.after_operand()? {
            return Err(refusal);
        }
        self.space()?;
        if self.op()?.is_some() {
            return Err(PredicateError::unsupported(construct::IN_EXISTS, at));
        }
        self.expect(")")?;
        self.ascend();
        Ok(Expression::Exists { path, filter })
    }

    /// A filter's conditions: comparisons of a path from `@`, joined by
    /// `&&`, with parentheses.
    fn conditions(&mut self) -> Result<Vec<Comparison>, PredicateError> {
        let mut conditions = Vec::new();
        loop {
            self.space()?;
            let at = self.pos;
            if self.rest().starts_with('!') && !self.rest().starts_with("!=") {
                return Err(PredicateError::unsupported(construct::NOT_IN_FILTER, at));
            }
            if self.keyword("exists")? {
                return Err(PredicateError::unsupported(construct::EXISTS_IN_FILTER, at));
            }
            if self.eat("(")? {
                self.descend()?;
                conditions.extend(self.conditions()?);
                self.expect(")")?;
                self.ascend();
            } else {
                conditions.push(self.comparison(true)?);
            }
            self.space()?;
            if self.rest().starts_with("||") {
                return Err(PredicateError::unsupported(
                    construct::OR_IN_FILTER,
                    self.pos,
                ));
            }
            if !self.eat("&&")? {
                return Ok(conditions);
            }
        }
    }

    /// A comparison operator at the cursor, read, and where it was.
    fn op(&mut self) -> Result<Option<(Operator, usize)>, PredicateError> {
        self.space()?;
        let at = self.pos;
        let rest = self.rest();
        let (op, len) = if rest.starts_with("==") {
            (Operator::Equal, 2)
        } else if rest.starts_with("!=") || rest.starts_with("<>") {
            (Operator::NotEqual, 2)
        } else if rest.starts_with("<=") {
            (Operator::LessOrEqual, 2)
        } else if rest.starts_with(">=") {
            (Operator::GreaterOrEqual, 2)
        } else if rest.starts_with('<') {
            (Operator::Less, 1)
        } else if rest.starts_with('>') {
            (Operator::Greater, 1)
        } else {
            return Ok(None);
        };
        self.pos += len;
        Ok(Some((op, at)))
    }

    /// The construct at the cursor that follows an operand and that the
    /// index cannot answer, if one is there.
    fn after_operand(&mut self) -> Result<Option<PredicateError>, PredicateError> {
        self.space()?;
        let at = self.pos;
        let rest = self.rest();
        if rest.starts_with(['+', '-', '*', '/', '%']) {
            return Ok(Some(PredicateError::unsupported(construct::ARITHMETIC, at)));
        }
        if rest.starts_with('?') {
            return Ok(Some(PredicateError::unsupported(
                construct::FILTER_OUTSIDE,
                at,
            )));
        }
        let word = self.word()?.unwrap_or_default();
        Ok(if word.eq_ignore_ascii_case("like_regex") {
            Some(PredicateError::unsupported(construct::LIKE_REGEX, at))
        } else if word.eq_ignore_ascii_case("starts") {
            Some(PredicateError::unsupported(construct::STARTS_WITH, at))
        } else if word.eq_ignore_ascii_case("is") {
            Some(PredicateError::unsupported(construct::IS_UNKNOWN, at))
        } else {
            None
        })
    }

    /// `comparison := operand op operand`, one side a path and the other a
    /// value; in a filter the path is from `@`.
    fn comparison(&mut self, in_filter: bool) -> Result<Comparison, PredicateError> {
        self.space()?;
        let left = self.operand(in_filter)?;
        if let Some(refusal) = self.after_operand()? {
            return Err(refusal);
        }
        let Some((op, at)) = self.op()? else {
            self.space()?;
            let at = self.pos;
            let ends = self.rest().is_empty() || self.rest().starts_with([')', '&', '|']);
            return Err(if ends {
                PredicateError::unsupported(construct::ALONE, at)
            } else {
                PredicateError::syntax(construct::TEXT, at)
            });
        };
        if in_filter && op == Operator::NotEqual {
            return Err(PredicateError::unsupported(
                construct::NOT_EQUAL_IN_FILTER,
                at,
            ));
        }
        self.space()?;
        let right = self.operand(in_filter)?;
        if let Some(refusal) = self.after_operand()? {
            return Err(refusal);
        }
        let (path, operator, value) = match (left, right) {
            (Side::Root(path) | Side::Current(path), Side::Value(value)) => (path, op, value),
            (Side::Value(value), Side::Root(path) | Side::Current(path)) => {
                (path, op.flipped(), value)
            }
            (Side::Value(_), Side::Value(_)) => {
                return Err(PredicateError::unsupported(construct::TWO_VALUES, at))
            }
            _ => return Err(PredicateError::unsupported(construct::TWO_PATHS, at)),
        };
        Ok(Comparison {
            path,
            operator,
            value,
            at,
        })
    }

    /// A path, a variable or a literal. In a filter a path is from `@`;
    /// outside one, from `$`.
    fn operand(&mut self, in_filter: bool) -> Result<Side, PredicateError> {
        self.space()?;
        let at = self.pos;
        let rest = self.rest();
        let Some(first) = rest.chars().next() else {
            return Err(PredicateError::syntax(construct::TEXT, at));
        };
        match first {
            '$' => {
                let after = &rest[1..];
                if after.starts_with('"') {
                    let (name, len) = self.string_at(at + 1)?;
                    self.pos = at + 1 + len;
                    return self.variable(name, at);
                }
                if after.starts_with(|c: char| !special(c)) {
                    self.pos += 1;
                    let Some(name) = self.word()? else {
                        return Err(PredicateError::syntax(construct::TEXT, self.pos));
                    };
                    self.pos += name.len();
                    return self.variable(Zeroizing::new(name.to_owned()), at);
                }
                if in_filter {
                    return Err(PredicateError::unsupported(construct::DOLLAR_IN_FILTER, at));
                }
                self.pos += 1;
                Ok(Side::Root(self.steps(at)?))
            }
            '@' => {
                if !in_filter {
                    return Err(PredicateError::unsupported(construct::AT_OUTSIDE, at));
                }
                self.pos += 1;
                Ok(Side::Current(self.steps(at)?))
            }
            '"' => {
                let (_, len) = self.string_at(at)?;
                self.pos += len;
                Ok(Side::Value(ValueAt::Literal {
                    start: at,
                    end: at + len,
                }))
            }
            '-' | '0'..='9' => {
                let len = number_len(rest).ok_or(PredicateError::syntax(construct::NUMBER, at))?;
                self.pos += len;
                Ok(Side::Value(ValueAt::Literal {
                    start: at,
                    end: at + len,
                }))
            }
            '+' => Err(PredicateError::unsupported(construct::ARITHMETIC, at)),
            _ => match self.word()? {
                Some(word @ ("true" | "false" | "null")) => {
                    self.pos += word.len();
                    Ok(Side::Value(ValueAt::Literal {
                        start: at,
                        end: at + word.len(),
                    }))
                }
                Some(word) if word.eq_ignore_ascii_case("last") => {
                    Err(PredicateError::unsupported(construct::LAST, at))
                }
                Some(word) if is_mode(word) => {
                    Err(PredicateError::unsupported(construct::MODE, at))
                }
                _ => Err(PredicateError::syntax(construct::TEXT, at)),
            },
        }
    }

    /// A variable named `name`, which takes no accessor. The name is the
    /// caller's text, and is wiped when the predicate is dropped.
    fn variable(&mut self, name: Zeroizing<String>, at: usize) -> Result<Side, PredicateError> {
        self.space()?;
        if self.rest().starts_with(['.', '[']) {
            return Err(PredicateError::unsupported(
                construct::VARIABLE_PATH,
                self.pos,
            ));
        }
        Ok(Side::Value(ValueAt::Variable { name, at }))
    }

    /// The JSON string at `at`, decoded, and its length in the text. Its
    /// escapes are JSON's. The decoded text is wiped when it drops: a
    /// literal's is a value, read only to check it, and a key's is moved
    /// into its path, which wipes it.
    fn string_at(&self, at: usize) -> Result<(Zeroizing<String>, usize), PredicateError> {
        let text = &self.text.as_bytes()[at..];
        string_end(text)
            .and_then(|end| Some((string_text(&text[..=end])?, end + 1)))
            .ok_or_else(|| PredicateError::syntax(construct::STRING, at))
    }

    /// The steps after `$` or `@`: `.name`, `."name"`, `[*]`, and the
    /// accessors refused by name. A step past a document's depth is
    /// refused before it is read, so the path held is never deeper than
    /// [`MAX_DEPTH`].
    ///
    /// The steps are read into the path itself, so a refusal part way
    /// drops a path, which wipes the keys already read.
    fn steps(&mut self, start: usize) -> Result<PathAt, PredicateError> {
        let mut path = JsonPath::root();
        loop {
            self.space()?;
            let at = self.pos;
            let rest = self.rest();
            if !rest.starts_with(['.', '[']) {
                break;
            }
            if path.segments().len() >= MAX_DEPTH {
                return Err(PredicateError::too_deep(start));
            }
            if let Some(after) = rest.strip_prefix('.') {
                let after_space = after.trim_start();
                let gap = after.len() - after_space.len();
                if after_space.starts_with("**") {
                    return Err(PredicateError::unsupported(construct::ANY_DEPTH, at));
                }
                if after_space.starts_with('*') {
                    return Err(PredicateError::unsupported(construct::ANY_MEMBER, at));
                }
                if after_space.starts_with('"') {
                    let (mut key, len) = self.string_at(at + 1 + gap)?;
                    self.pos = at + 1 + gap + len;
                    path.push(Segment::Key(std::mem::take(&mut *key)));
                    continue;
                }
                self.pos = at + 1;
                let Some(name) = self.word()? else {
                    return Err(PredicateError::syntax(construct::TEXT, self.pos));
                };
                self.pos += name.len();
                if self.peek()? == Some('(') {
                    return Err(PredicateError::unsupported(construct::METHOD, at));
                }
                path.push(Segment::Key(name.to_owned()));
            } else {
                self.pos += 1;
                self.space()?;
                if self.eat("*")? {
                    self.expect("]")?;
                    path.push(Segment::Wildcard);
                } else if self.rest().starts_with(|c: char| c.is_ascii_digit()) {
                    let digits = self
                        .rest()
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(self.rest().len());
                    self.pos += digits;
                    self.space()?;
                    if self.rest().starts_with(']') {
                        return Err(PredicateError {
                            kind: PredicateErrorKind::Position,
                            construct: construct::POSITION,
                            at,
                        });
                    }
                    return Err(PredicateError::unsupported(construct::SLICE, at));
                } else if self.keyword("last")? {
                    return Err(PredicateError::unsupported(construct::LAST, at));
                } else {
                    return Err(PredicateError::unsupported(construct::SUBSCRIPT, at));
                }
            }
        }
        Ok(PathAt { path, at: start })
    }
}

/// The length of the JSON number at the front of `text`:
/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, followed by
/// something that does not continue it. `None` for text that is not one.
fn number_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = usize::from(bytes.first() == Some(&b'-'));
    let digits = |from: usize| {
        bytes[from..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    };
    match bytes.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i += digits(i),
        _ => return None,
    }
    if bytes.get(i) == Some(&b'.') {
        let fraction = digits(i + 1);
        if fraction == 0 {
            return None;
        }
        i += 1 + fraction;
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let exponent = digits(j);
        if exponent == 0 {
            return None;
        }
        i = j + exponent;
    }
    match text[i..].chars().next() {
        Some(c) if !special(c) || c == '.' => None,
        _ => Some(i),
    }
}

/// Whether `word` is a mode word, `strict` or `lax`, in any case.
fn is_mode(word: &str) -> bool {
    word.eq_ignore_ascii_case("strict") || word.eq_ignore_ascii_case("lax")
}

/// Parse a predicate's text.
///
/// # Errors
///
/// A [`PredicateError`] for text the grammar does not read
/// ([`PredicateErrorKind::Syntax`]) or a construct it reads and the index
/// cannot answer ([`PredicateErrorKind::Unsupported`],
/// [`PredicateErrorKind::TooDeep`], [`PredicateErrorKind::Position`]), at
/// the byte where it starts.
pub fn parse(text: &str) -> Result<Expression, PredicateError> {
    let mut parser = Parser {
        text,
        pos: 0,
        depth: 0,
    };
    parser.space()?;
    let at = parser.pos;
    if parser.word()?.is_some_and(is_mode) {
        return Err(PredicateError::unsupported(construct::MODE, at));
    }
    let expression = parser.or()?;
    parser.space()?;
    if !parser.rest().is_empty() {
        return Err(PredicateError::syntax(construct::TRAILING, parser.pos));
    }
    Ok(expression)
}

#[cfg(test)]
mod tests;
