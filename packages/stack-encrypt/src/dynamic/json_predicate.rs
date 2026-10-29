//! `match`'s predicate: the SQL/JSON path predicates the JSON index can
//! answer, parsed from the caller's text and compiled onto the inputs of
//! the other JSON operators.
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
//! `OpSpec::Match`'s documentation runs one through the data plan. The
//! grammar and the compilation are documented with the operator, in
//! the [`json_query`](super::json_query) module docs. This module holds the
//! parser ([`parse`]), which reads the text into an [`Ast`] and refuses
//! what the grammar does not read at the byte where it stops, and the
//! compiler ([`compile`]), which binds the values and maps each comparison
//! onto the inputs `eq_at`, `selector`, the orderings and `element_match`
//! take, so that every leaf is derived by that operator's own code
//! ([`derive`]).
//!
//! A refusal names a construct in the grammar's words and an offset, never
//! a slice of the text: a key name or a value in it can be customer data.
//! The text itself is the caller's buffer, wiped when it drops; the tree
//! holds offsets into it, the key names in [`JsonPath`]s, which wipe them,
//! and the values in [`Parsed`], which wipes them.

use serde_json::Value;
use zeroize::Zeroizing;

use super::json_query::{
    derive_input, eql, json_reason, leaf, member_of, ordered_path_of, Bounds, Compare, Input,
    Parsed, Predicate,
};
use super::query::{OpSpec, Operand};
use super::{Error, Reason};
use crate::json::{parse_text, JsonOptions, JsonPath, Segment, MAX_DEPTH};
use crate::{KeysetCipher, Label, Pending};

/// How deeply a predicate may nest parentheses, `!` and `exists`. The
/// parser descends once per level, so the bound keeps a hostile predicate
/// from overflowing the stack; the SQL evaluates the compiled tree by
/// recursion too.
pub(super) const MAX_NESTING: usize = 32;

// The constructs a refusal names, in the grammar's own words.
const C_TEXT: &str = "text the grammar does not read";
const C_TRAILING: &str = "text after the predicate";
const C_STRING: &str = "a string literal";
const C_NUMBER: &str = "a numeric literal";
const C_MODE: &str = "a mode (`strict`, `lax`)";
const C_ARITHMETIC: &str = "arithmetic (`+`, `-`, `*`, `/`, `%`)";
const C_LIKE_REGEX: &str = "`like_regex`";
const C_STARTS_WITH: &str = "`starts with`";
const C_IS_UNKNOWN: &str = "`is unknown`";
const C_METHOD: &str = "a method (`.name()`)";
const C_ANY_MEMBER: &str = "`.*`";
const C_ANY_DEPTH: &str = "`.**`";
const C_SLICE: &str = "an array slice or list (`[a to b]`, `[a, b]`)";
const C_LAST: &str = "`last`";
const C_SUBSCRIPT: &str = "a subscript other than `[*]`";
const C_POSITION: &str = "a position (`[2]`)";
const C_AT_OUTSIDE: &str = "`@` outside a filter";
const C_DOLLAR_IN_FILTER: &str = "a `$` path in a filter";
const C_VARIABLE_PATH: &str = "an accessor on a variable";
const C_TWO_PATHS: &str = "a comparison of two paths";
const C_TWO_VALUES: &str = "a comparison of two values";
const C_ALONE: &str = "an operand with no comparison";
const C_FILTER_OUTSIDE: &str = "a filter outside `exists`";
const C_AFTER_FILTER: &str = "an accessor after a filter";
const C_IN_EXISTS: &str = "a comparison inside `exists`";
const C_OR_IN_FILTER: &str = "`||` in a filter";
const C_NOT_IN_FILTER: &str = "`!` in a filter";
const C_NE_IN_FILTER: &str = "`!=` in a filter";
const C_EXISTS_IN_FILTER: &str = "`exists` in a filter";
const C_ELEMENTS_THEMSELVES: &str = "an ordering of an array's elements themselves";
const C_WHOLE_ELEMENT: &str = "`@` beside another condition";
const C_FILTER_WILDCARD: &str = "a filter on a path with no wildcard";
const C_MEMBER_WILDCARD: &str = "a wildcard in a filter's member";
const C_NOT_EQUAL: &str = "`!=` at a path with a wildcard";
const C_VALUE: &str = "a value";
const C_VARIABLE: &str = "a variable";
const C_NESTING: &str = "nesting";

/// A refusal at a byte of the predicate's text.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    reason: Reason,
    construct: &'static str,
    at: usize,
}

impl Refusal {
    fn syntax(construct: &'static str, at: usize) -> Self {
        Self {
            reason: Reason::JsonPredicateSyntax,
            construct,
            at,
        }
    }

    fn unsupported(construct: &'static str, at: usize) -> Self {
        Self {
            reason: Reason::JsonPredicateUnsupported,
            construct,
            at,
        }
    }
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        Error::Predicate {
            field: None,
            reason: refusal.reason,
            construct: refusal.construct,
            at: refusal.at,
        }
    }
}

/// A comparison operator, as the text spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
}

impl Op {
    /// The operator with its operands swapped: `1 < $.a` is `$.a > 1`.
    fn flipped(self) -> Self {
        match self {
            Op::Lt => Op::Gt,
            Op::Lte => Op::Gte,
            Op::Gt => Op::Lt,
            Op::Gte => Op::Lte,
            same => same,
        }
    }

    /// How an element-scoped filter's condition compares; `None` for
    /// `!=`, which a filter does not take.
    fn compare(self) -> Option<Compare> {
        match self {
            Op::Eq => Some(Compare::Eq),
            Op::Lt => Some(Compare::Lt),
            Op::Lte => Some(Compare::Lte),
            Op::Gt => Some(Compare::Gt),
            Op::Gte => Some(Compare::Gte),
            Op::Ne => None,
        }
    }
}

/// A path in the text: `$` or `@` and the steps after it, and where it
/// starts.
#[derive(Debug)]
struct PathAt {
    path: JsonPath,
    at: usize,
}

/// A value in the text: a literal, by its bytes, or a variable, by name.
#[derive(Debug, PartialEq, Eq)]
enum ValueAt {
    /// `"…"`, a number, `true`, `false` or `null`: the literal's bytes,
    /// `start..end`, which are JSON text.
    Literal { start: usize, end: usize },
    /// `$name` or `$"name"`.
    Variable { name: String, at: usize },
}

impl ValueAt {
    fn at(&self) -> usize {
        match self {
            ValueAt::Literal { start, .. } => *start,
            ValueAt::Variable { at, .. } => *at,
        }
    }
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

/// A comparison of a path with a value, the path on the left.
#[derive(Debug)]
struct Comparison {
    path: PathAt,
    op: Op,
    value: ValueAt,
    /// Where the operator is.
    at: usize,
}

/// A predicate as the text writes it.
#[derive(Debug)]
enum Ast {
    And(Vec<Ast>),
    Or(Vec<Ast>),
    Not(Box<Ast>),
    Compare(Comparison),
    /// `exists(path)`, or `exists(path ? (conditions))`, each condition a
    /// comparison of a path from `@`.
    Exists {
        path: PathAt,
        filter: Option<Vec<Comparison>>,
    },
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
    fn space(&mut self) -> Result<(), Refusal> {
        loop {
            let rest = self.rest();
            let trimmed = rest.trim_start();
            self.pos += rest.len() - trimmed.len();
            if let Some(comment) = trimmed.strip_prefix("/*") {
                let Some(end) = comment.find("*/") else {
                    return Err(Refusal::syntax(C_TEXT, self.pos));
                };
                self.pos += 2 + end + 2;
            } else {
                return Ok(());
            }
        }
    }

    /// The next character after any space, unread.
    fn peek(&mut self) -> Result<Option<char>, Refusal> {
        self.space()?;
        Ok(self.rest().chars().next())
    }

    /// Read `token` if it is next.
    fn eat(&mut self, token: &str) -> Result<bool, Refusal> {
        self.space()?;
        if self.rest().starts_with(token) {
            self.pos += token.len();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn expect(&mut self, token: &str) -> Result<(), Refusal> {
        if self.eat(token)? {
            Ok(())
        } else {
            Err(Refusal::syntax(C_TEXT, self.pos))
        }
    }

    /// The name at the cursor, unread: a run of characters that are not
    /// punctuation, not starting with a digit.
    fn word(&mut self) -> Result<Option<&'t str>, Refusal> {
        self.space()?;
        let rest = self.rest();
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return Ok(None);
        }
        let end = rest.find(special).unwrap_or(rest.len());
        Ok((end > 0).then(|| &rest[..end]))
    }

    /// One more level of nesting, refused past [`MAX_NESTING`].
    fn descend(&mut self) -> Result<(), Refusal> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(Refusal {
                reason: Reason::JsonPredicateTooDeep,
                construct: C_NESTING,
                at: self.pos,
            });
        }
        Ok(())
    }

    fn ascend(&mut self) {
        self.depth -= 1;
    }

    /// `or := and ('||' and)*`.
    fn or(&mut self) -> Result<Ast, Refusal> {
        let mut terms = vec![self.and()?];
        while self.eat("||")? {
            terms.push(self.and()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Ast::Or(terms)
        })
    }

    /// `and := unary ('&&' unary)*`.
    fn and(&mut self) -> Result<Ast, Refusal> {
        let mut terms = vec![self.unary()?];
        while self.eat("&&")? {
            terms.push(self.unary()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Ast::And(terms)
        })
    }

    /// `unary := '!' primary | primary`. As in PostgreSQL, `!` takes a
    /// parenthesised predicate or `exists`, not a bare comparison.
    fn unary(&mut self) -> Result<Ast, Refusal> {
        self.space()?;
        if self.rest().starts_with('!') && !self.rest().starts_with("!=") {
            self.pos += 1;
            self.descend()?;
            let at = self.pos;
            let negated = match self.peek()? {
                Some('(') => self.primary()?,
                _ if self.keyword("exists")? => self.primary()?,
                _ => return Err(Refusal::syntax(C_TEXT, at)),
            };
            self.ascend();
            return Ok(Ast::Not(Box::new(negated)));
        }
        self.primary()
    }

    /// Whether the word at the cursor is `keyword`, in any case, as
    /// PostgreSQL reads `exists`.
    fn keyword(&mut self, keyword: &str) -> Result<bool, Refusal> {
        Ok(self
            .word()?
            .is_some_and(|word| word.eq_ignore_ascii_case(keyword)))
    }

    /// `primary := '(' or ')' | 'exists' '(' path filter? ')' | comparison`.
    fn primary(&mut self) -> Result<Ast, Refusal> {
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
            return Err(Refusal::syntax(C_TEXT, self.pos));
        }
        let comparison = self.comparison(false)?;
        Ok(Ast::Compare(comparison))
    }

    /// The inside of `exists(…)`, the `(` read.
    fn exists(&mut self) -> Result<Ast, Refusal> {
        self.descend()?;
        self.space()?;
        let at = self.pos;
        let path = match self.operand(false)? {
            Side::Root(path) => path,
            Side::Current(_) => return Err(Refusal::unsupported(C_AT_OUTSIDE, at)),
            Side::Value(_) => return Err(Refusal::syntax(C_TEXT, at)),
        };
        let filter = if self.eat("?")? {
            self.expect("(")?;
            self.descend()?;
            let conditions = self.conditions()?;
            self.expect(")")?;
            self.ascend();
            let at = self.pos;
            match self.peek()? {
                Some('.' | '[') => return Err(Refusal::unsupported(C_AFTER_FILTER, at)),
                Some('?') => return Err(Refusal::unsupported(C_FILTER_OUTSIDE, at)),
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
            return Err(Refusal::unsupported(C_IN_EXISTS, at));
        }
        self.expect(")")?;
        self.ascend();
        Ok(Ast::Exists { path, filter })
    }

    /// A filter's conditions: comparisons of a path from `@`, joined by
    /// `&&`, with parentheses.
    fn conditions(&mut self) -> Result<Vec<Comparison>, Refusal> {
        let mut conditions = Vec::new();
        loop {
            self.space()?;
            let at = self.pos;
            if self.rest().starts_with('!') && !self.rest().starts_with("!=") {
                return Err(Refusal::unsupported(C_NOT_IN_FILTER, at));
            }
            if self.keyword("exists")? {
                return Err(Refusal::unsupported(C_EXISTS_IN_FILTER, at));
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
                return Err(Refusal::unsupported(C_OR_IN_FILTER, self.pos));
            }
            if !self.eat("&&")? {
                return Ok(conditions);
            }
        }
    }

    /// A comparison operator at the cursor, read, and where it was.
    fn op(&mut self) -> Result<Option<(Op, usize)>, Refusal> {
        self.space()?;
        let at = self.pos;
        let rest = self.rest();
        let (op, len) = if rest.starts_with("==") {
            (Op::Eq, 2)
        } else if rest.starts_with("!=") || rest.starts_with("<>") {
            (Op::Ne, 2)
        } else if rest.starts_with("<=") {
            (Op::Lte, 2)
        } else if rest.starts_with(">=") {
            (Op::Gte, 2)
        } else if rest.starts_with('<') {
            (Op::Lt, 1)
        } else if rest.starts_with('>') {
            (Op::Gt, 1)
        } else {
            return Ok(None);
        };
        self.pos += len;
        Ok(Some((op, at)))
    }

    /// The construct at the cursor that follows an operand and that the
    /// index cannot answer, if one is there.
    fn after_operand(&mut self) -> Result<Option<Refusal>, Refusal> {
        self.space()?;
        let at = self.pos;
        let rest = self.rest();
        if rest.starts_with(['+', '-', '*', '/', '%']) {
            return Ok(Some(Refusal::unsupported(C_ARITHMETIC, at)));
        }
        if rest.starts_with('?') {
            return Ok(Some(Refusal::unsupported(C_FILTER_OUTSIDE, at)));
        }
        let word = self.word()?.unwrap_or_default();
        Ok(if word.eq_ignore_ascii_case("like_regex") {
            Some(Refusal::unsupported(C_LIKE_REGEX, at))
        } else if word.eq_ignore_ascii_case("starts") {
            Some(Refusal::unsupported(C_STARTS_WITH, at))
        } else if word.eq_ignore_ascii_case("is") {
            Some(Refusal::unsupported(C_IS_UNKNOWN, at))
        } else {
            None
        })
    }

    /// `comparison := operand op operand`, one side a path and the other a
    /// value; in a filter the path is from `@`.
    fn comparison(&mut self, in_filter: bool) -> Result<Comparison, Refusal> {
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
                Refusal::unsupported(C_ALONE, at)
            } else {
                Refusal::syntax(C_TEXT, at)
            });
        };
        if in_filter && op == Op::Ne {
            return Err(Refusal::unsupported(C_NE_IN_FILTER, at));
        }
        self.space()?;
        let right = self.operand(in_filter)?;
        if let Some(refusal) = self.after_operand()? {
            return Err(refusal);
        }
        let (path, op, value) = match (left, right) {
            (Side::Root(path) | Side::Current(path), Side::Value(value)) => (path, op, value),
            (Side::Value(value), Side::Root(path) | Side::Current(path)) => {
                (path, op.flipped(), value)
            }
            (Side::Value(_), Side::Value(_)) => return Err(Refusal::unsupported(C_TWO_VALUES, at)),
            _ => return Err(Refusal::unsupported(C_TWO_PATHS, at)),
        };
        Ok(Comparison {
            path,
            op,
            value,
            at,
        })
    }

    /// A path, a variable or a literal. In a filter a path is from `@`;
    /// outside one, from `$`.
    fn operand(&mut self, in_filter: bool) -> Result<Side, Refusal> {
        self.space()?;
        let at = self.pos;
        let rest = self.rest();
        let Some(first) = rest.chars().next() else {
            return Err(Refusal::syntax(C_TEXT, at));
        };
        match first {
            '$' => {
                let after = &rest[1..];
                if after.starts_with('"') {
                    let (mut name, len) = self.string_at(at + 1)?;
                    self.pos = at + 1 + len;
                    return self.variable(std::mem::take(&mut *name), at);
                }
                if after.starts_with(|c: char| !special(c)) {
                    self.pos += 1;
                    let Some(name) = self.word()? else {
                        return Err(Refusal::syntax(C_TEXT, self.pos));
                    };
                    self.pos += name.len();
                    return self.variable(name.to_owned(), at);
                }
                if in_filter {
                    return Err(Refusal::unsupported(C_DOLLAR_IN_FILTER, at));
                }
                self.pos += 1;
                Ok(Side::Root(self.steps(at)?))
            }
            '@' => {
                if !in_filter {
                    return Err(Refusal::unsupported(C_AT_OUTSIDE, at));
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
                let len = number_len(rest).ok_or(Refusal::syntax(C_NUMBER, at))?;
                self.pos += len;
                Ok(Side::Value(ValueAt::Literal {
                    start: at,
                    end: at + len,
                }))
            }
            '+' => Err(Refusal::unsupported(C_ARITHMETIC, at)),
            _ => match self.word()? {
                Some(word @ ("true" | "false" | "null")) => {
                    self.pos += word.len();
                    Ok(Side::Value(ValueAt::Literal {
                        start: at,
                        end: at + word.len(),
                    }))
                }
                Some(word) if word.eq_ignore_ascii_case("last") => {
                    Err(Refusal::unsupported(C_LAST, at))
                }
                Some(word) if is_mode(word) => Err(Refusal::unsupported(C_MODE, at)),
                _ => Err(Refusal::syntax(C_TEXT, at)),
            },
        }
    }

    /// A variable named `name`, which takes no accessor.
    fn variable(&mut self, name: String, at: usize) -> Result<Side, Refusal> {
        self.space()?;
        if self.rest().starts_with(['.', '[']) {
            return Err(Refusal::unsupported(C_VARIABLE_PATH, self.pos));
        }
        Ok(Side::Value(ValueAt::Variable { name, at }))
    }

    /// The JSON string at `at`, decoded, and its length in the text. Its
    /// escapes are JSON's. The decoded text is wiped when it drops: a
    /// literal's is a value, read only to check it, and a key's is moved
    /// into its path, which wipes it.
    fn string_at(&self, at: usize) -> Result<(Zeroizing<String>, usize), Refusal> {
        let text = &self.text[at..];
        let mut escaped = false;
        for (end, byte) in text.bytes().enumerate().skip(1) {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => {
                    let decoded = serde_json::from_str(&text[..=end])
                        .map(Zeroizing::new)
                        .map_err(|_| Refusal::syntax(C_STRING, at))?;
                    return Ok((decoded, end + 1));
                }
                (false, _) => {}
            }
        }
        Err(Refusal::syntax(C_STRING, at))
    }

    /// The steps after `$` or `@`: `.name`, `."name"`, `[*]`, and the
    /// accessors refused by name. A step past a document's depth is
    /// refused before it is read, so the path held is never deeper than
    /// [`MAX_DEPTH`].
    fn steps(&mut self, start: usize) -> Result<PathAt, Refusal> {
        let mut segments = Vec::new();
        loop {
            self.space()?;
            let at = self.pos;
            let rest = self.rest();
            if !rest.starts_with(['.', '[']) {
                break;
            }
            if segments.len() >= MAX_DEPTH {
                return Err(Refusal {
                    reason: Reason::JsonPredicateTooDeep,
                    construct: C_NESTING,
                    at: start,
                });
            }
            if let Some(after) = rest.strip_prefix('.') {
                let after_space = after.trim_start();
                let gap = after.len() - after_space.len();
                if after_space.starts_with("**") {
                    return Err(Refusal::unsupported(C_ANY_DEPTH, at));
                }
                if after_space.starts_with('*') {
                    return Err(Refusal::unsupported(C_ANY_MEMBER, at));
                }
                if after_space.starts_with('"') {
                    let (mut key, len) = self.string_at(at + 1 + gap)?;
                    self.pos = at + 1 + gap + len;
                    segments.push(Segment::Key(std::mem::take(&mut *key)));
                    continue;
                }
                self.pos = at + 1;
                let Some(name) = self.word()? else {
                    return Err(Refusal::syntax(C_TEXT, self.pos));
                };
                self.pos += name.len();
                if self.peek()? == Some('(') {
                    return Err(Refusal::unsupported(C_METHOD, at));
                }
                segments.push(Segment::Key(name.to_owned()));
            } else {
                self.pos += 1;
                self.space()?;
                if self.eat("*")? {
                    self.expect("]")?;
                    segments.push(Segment::Wildcard);
                } else if self.rest().starts_with(|c: char| c.is_ascii_digit()) {
                    let digits = self
                        .rest()
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(self.rest().len());
                    self.pos += digits;
                    self.space()?;
                    if self.rest().starts_with(']') {
                        return Err(Refusal {
                            reason: Reason::JsonPathPosition,
                            construct: C_POSITION,
                            at,
                        });
                    }
                    return Err(Refusal::unsupported(C_SLICE, at));
                } else if self.keyword("last")? {
                    return Err(Refusal::unsupported(C_LAST, at));
                } else {
                    return Err(Refusal::unsupported(C_SUBSCRIPT, at));
                }
            }
        }
        Ok(PathAt {
            path: JsonPath::of(segments),
            at: start,
        })
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
fn parse(text: &str) -> Result<Ast, Refusal> {
    let mut parser = Parser {
        text,
        pos: 0,
        depth: 0,
    };
    parser.space()?;
    let at = parser.pos;
    if parser.word()?.is_some_and(is_mode) {
        return Err(Refusal::unsupported(C_MODE, at));
    }
    let ast = parser.or()?;
    parser.space()?;
    if !parser.rest().is_empty() {
        return Err(Refusal::syntax(C_TRAILING, parser.pos));
    }
    Ok(ast)
}

/// A predicate compiled: a tree of the inputs of the operators whose
/// operands are its leaves.
#[derive(PartialEq)]
pub(super) enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    /// One leaf: an operator and the input it derives from, checked.
    Leaf(OpSpec, Input),
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::And(children) => f.debug_tuple("And").field(children).finish(),
            Node::Or(children) => f.debug_tuple("Or").field(children).finish(),
            Node::Not(child) => f.debug_tuple("Not").field(child).finish(),
            // The input holds the predicate's values: the operator alone.
            Node::Leaf(op, _) => f.debug_tuple("Leaf").field(op).finish(),
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
pub(super) fn compile(
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
    let ast = parse(text)?;
    Ok(simplify(compiler.node(ast, false)?))
}

impl Compiler<'_> {
    /// The node for `ast`, which sits under an odd number of `!` when
    /// `negated`. `and` and `or` are monotone in each child, so only a `!`
    /// turns a child's NULL into a different row set than its false; see
    /// [`Compiler::comparison`].
    fn node(&self, ast: Ast, negated: bool) -> Result<Node, Error> {
        Ok(match ast {
            Ast::And(terms) => Node::And(
                terms
                    .into_iter()
                    .map(|t| self.node(t, negated))
                    .collect::<Result<_, _>>()?,
            ),
            Ast::Or(terms) => Node::Or(
                terms
                    .into_iter()
                    .map(|t| self.node(t, negated))
                    .collect::<Result<_, _>>()?,
            ),
            Ast::Not(inner) => Node::Not(Box::new(self.node(*inner, !negated)?)),
            Ast::Compare(comparison) => self.comparison(comparison, negated)?,
            Ast::Exists { path, filter: None } => {
                Node::Leaf(OpSpec::Selector, Input::Path(path.path))
            }
            Ast::Exists {
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
                .map_err(|error| {
                    Refusal {
                        reason: json_reason(error),
                        construct: C_VALUE,
                        at: *start,
                    }
                    .into()
                }),
            ValueAt::Variable { name, at } => self
                .vars
                .get(name)
                .map(|value| Parsed(value.clone()))
                .ok_or_else(|| {
                    Refusal {
                        reason: Reason::JsonPredicateUnknownVariable,
                        construct: C_VARIABLE,
                        at: *at,
                    }
                    .into()
                }),
        }
    }

    /// The value of `at`, a scalar: what equality takes.
    fn scalar(&self, at: &ValueAt) -> Result<Parsed, Error> {
        let value = self.value(at)?;
        if matches!(value.0, Value::Object(_) | Value::Array(_)) {
            return Err(value_type(at));
        }
        Ok(value)
    }

    /// The value of `at`, a number or a string: what an ordering takes.
    fn ordered(&self, at: &ValueAt) -> Result<Parsed, Error> {
        let value = self.value(at)?;
        leaf(&value.0).map_err(|_| value_type(at))?;
        Ok(value)
    }

    /// `path op value`, under an odd number of `!` when `negated`.
    fn comparison(&self, comparison: Comparison, negated: bool) -> Result<Node, Error> {
        let Comparison {
            path,
            op,
            value,
            at,
        } = comparison;
        let wild = !path.path.is_positional();
        let (compare, operator) = match op {
            // `==`: containment of the value at the path, exact; at a
            // wildcard, of any element.
            Op::Eq => {
                return Ok(Node::Leaf(
                    OpSpec::EqAt,
                    Input::At(path.path, self.scalar(&value)?),
                ))
            }
            // `!=` over several elements is true when one differs, which
            // containment cannot say.
            Op::Ne if wild => {
                return Err(Refusal {
                    reason: Reason::JsonPredicateNotEqualAtWildcard,
                    construct: C_NOT_EQUAL,
                    at,
                }
                .into())
            }
            // `!=` at one node: a node there that is not the value.
            Op::Ne => {
                let value = self.scalar(&value)?;
                return Ok(Node::And(vec![
                    Node::Leaf(OpSpec::Selector, Input::Path(path.path.clone())),
                    Node::Not(Box::new(Node::Leaf(
                        OpSpec::EqAt,
                        Input::At(path.path, value),
                    ))),
                ]));
            }
            Op::Lt => (Compare::Lt, OpSpec::LtAt),
            Op::Lte => (Compare::Lte, OpSpec::LteAt),
            Op::Gt => (Compare::Gt, OpSpec::GtAt),
            Op::Gte => (Compare::Gte, OpSpec::GteAt),
        };
        Ok(if wild {
            // An ordering at a wildcard: some element's field, which is
            // `element_match` on the array through the last wildcard.
            let value = self.ordered(&value)?;
            let mut segments = path.path.segments().to_vec();
            let last = segments
                .iter()
                .rposition(|segment| *segment == Segment::Wildcard)
                .unwrap_or_default();
            let member = segments.split_off(last + 1);
            if member.is_empty() {
                return Err(Refusal::unsupported(C_ELEMENTS_THEMSELVES, at).into());
            }
            let base = JsonPath::of(segments);
            let predicate = self.member(&base, JsonPath::of(member), compare, value)?;
            Node::Leaf(
                OpSpec::ElementMatch,
                Input::Elements(self.bound, vec![predicate]),
            )
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
            let mut leaves = vec![Node::Leaf(OpSpec::Selector, Input::Path(path.clone()))];
            if negated {
                leaves.push(Node::Not(Box::new(Node::Leaf(
                    OpSpec::EqAt,
                    Input::At(path.clone(), Parsed(Value::Null)),
                ))));
            }
            leaves.push(Node::Leaf(operator, Input::At(path, value)));
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
        if path.path.is_positional() {
            return Err(Refusal {
                reason: Reason::JsonPathNoWildcard,
                construct: C_FILTER_WILDCARD,
                at: path.at,
            }
            .into());
        }
        let base = path.path;
        for condition in &conditions {
            if base.segments().len() + condition.path.path.segments().len() > MAX_DEPTH {
                return Err(Refusal {
                    reason: Reason::JsonPredicateTooDeep,
                    construct: C_NESTING,
                    at: path.at,
                }
                .into());
            }
            if !condition.path.path.is_positional() {
                return Err(Refusal {
                    reason: Reason::JsonPathWildcard,
                    construct: C_MEMBER_WILDCARD,
                    at: condition.path.at,
                }
                .into());
            }
        }
        if let [only] = conditions.as_slice() {
            if only.op == Op::Eq {
                let full = only.path.path.segments().iter().fold(
                    base.segments().to_vec(),
                    |mut at, segment| {
                        at.push(segment.clone());
                        at
                    },
                );
                return Ok(Node::Leaf(
                    OpSpec::EqAt,
                    Input::At(JsonPath::of(full), self.scalar(&only.value)?),
                ));
            }
        }
        let mut predicates = Vec::with_capacity(conditions.len());
        for condition in conditions {
            let Some(compare) = condition.op.compare() else {
                return Err(Refusal::unsupported(C_NE_IN_FILTER, condition.at).into());
            };
            if condition.path.path.segments().is_empty() {
                let construct = if compare == Compare::Eq {
                    C_WHOLE_ELEMENT
                } else {
                    C_ELEMENTS_THEMSELVES
                };
                return Err(Refusal::unsupported(construct, condition.path.at).into());
            }
            let value = self.ordered(&condition.value)?;
            predicates.push(self.member(&base, condition.path.path, compare, value)?);
        }
        Ok(Node::Leaf(
            OpSpec::ElementMatch,
            Input::Elements(self.bound, predicates),
        ))
    }
}

fn value_type(at: &ValueAt) -> Error {
    Refusal {
        reason: Reason::JsonPredicateValueType,
        construct: C_VALUE,
        at: at.at(),
    }
    .into()
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
    fn of(node: Node, leaves: &mut Vec<(OpSpec, Input)>) -> Result<Self, Error> {
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
            Node::Leaf(op, input) => {
                let shape = match op {
                    OpSpec::EqAt => Shape::Leaf("contains", None),
                    OpSpec::Selector => Shape::Leaf("exists", None),
                    OpSpec::LtAt => Shape::Leaf("cmp", Some("lt")),
                    OpSpec::LteAt => Shape::Leaf("cmp", Some("lte")),
                    OpSpec::GtAt => Shape::Leaf("cmp", Some("gt")),
                    OpSpec::GteAt => Shape::Leaf("cmp", Some("gte")),
                    OpSpec::ElementMatch => Shape::Leaf("elements", None),
                    _ => return Err(Error::Internal),
                };
                leaves.push((op, input));
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
fn operand_value(operand: Operand) -> Result<Value, crate::Error> {
    match operand {
        Operand::One(bytes) => {
            serde_json::from_slice(&bytes).map_err(|error| crate::Error::Other(Box::new(error)))
        }
        Operand::Text(text) => Ok(Value::String(text)),
        _ => Err(crate::Error::Other(
            "a predicate leaf derives one operand".into(),
        )),
    }
}

/// Derive a compiled predicate's operand: each leaf by its own operator's
/// derivation ([`derive_input`]), all in one pending, put back into the
/// tree.
pub(super) fn derive<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    label: &Label,
    options: &JsonOptions,
    node: Node,
) -> Result<Pending<'a, Operand, K>, Error> {
    let mut leaves = Vec::new();
    let shape = Shape::of(node, &mut leaves)?;
    let operands = leaves
        .into_iter()
        .map(|(op, input)| {
            derive_input(keyset, label, options, op, input).map(|p| p.try_map(operand_value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Pending::all(keyset, operands)
        .try_map(move |operands| eql(&shape.fill(&mut operands.into_iter())?).map(Operand::One)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sem::TermError;

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
            Node::Leaf(op, Input::At(path, value)) => format!("{}({path}, {})", op.name(), value.0),
            Node::Leaf(op, Input::Path(path)) => format!("{}({path})", op.name()),
            Node::Leaf(op, Input::Elements(bound, predicates)) => {
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
                format!("{}({bound}, [{}])", op.name(), members.join("; "))
            }
            Node::Leaf(op, _) => op.name().to_owned(),
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
                ("strict $.a == 1", C_MODE, 0),
                ("STRICT $.a == 1", C_MODE, 0),
                ("$.a == Lax", C_MODE, 7),
                (r#"$.a LIKE_REGEX "x""#, C_LIKE_REGEX, 4),
                (r#"$.a Starts with "x""#, C_STARTS_WITH, 4),
                ("$.a IS unknown", C_IS_UNKNOWN, 4),
                ("$.a[LAST] == 1", C_LAST, 3),
                ("$.a == LAST", C_LAST, 7),
                (r#"exists($.a like_regex "x")"#, C_LIKE_REGEX, 11),
                ("exists($.a + 1)", C_ARITHMETIC, 11),
                (
                    "exists($.a[*] ? (@ == 1) starts with \"x\")",
                    C_STARTS_WITH,
                    25,
                ),
                ("  lax $.a == 1", C_MODE, 2),
                ("$.a + 1 == 2", C_ARITHMETIC, 4),
                ("$.a == 1 - 2", C_ARITHMETIC, 9),
                ("$.a == +1", C_ARITHMETIC, 7),
                (r#"$.a like_regex "x""#, C_LIKE_REGEX, 4),
                (r#"$.a starts with "x""#, C_STARTS_WITH, 4),
                ("$.a is unknown", C_IS_UNKNOWN, 4),
                ("$.a.size() == 1", C_METHOD, 3),
                ("$.a.type () == 1", C_METHOD, 3),
                ("$.* == 1", C_ANY_MEMBER, 1),
                ("$.** == 1", C_ANY_DEPTH, 1),
                ("$.a[1 to 2] == 1", C_SLICE, 3),
                ("$.a[1, 2] == 1", C_SLICE, 3),
                ("$.a[last] == 1", C_LAST, 3),
                ("$.a == last", C_LAST, 7),
                ("$.a == lax", C_MODE, 7),
                ("$.a[$i] == 1", C_SUBSCRIPT, 3),
                ("@ == 1", C_AT_OUTSIDE, 0),
                ("$.a == $.b", C_TWO_PATHS, 4),
                ("1 == 1", C_TWO_VALUES, 2),
                ("$x == $y", C_TWO_VALUES, 3),
                ("$.a", C_ALONE, 3),
                ("$.a && $.b == 1", C_ALONE, 4),
                ("true", C_ALONE, 4),
                ("$.a[*] ? (@ == 1) == 1", C_FILTER_OUTSIDE, 7),
                ("exists($.a[*] ? (@ == 1).b)", C_AFTER_FILTER, 24),
                ("exists($.a[*] ? (@ == 1) ? (@ == 2))", C_FILTER_OUTSIDE, 24),
                ("exists($.a == 1)", C_IN_EXISTS, 7),
                ("exists(@)", C_AT_OUTSIDE, 7),
                (
                    "exists($.a[*] ? (@.b == 1 || @.c == 2))",
                    C_OR_IN_FILTER,
                    26,
                ),
                ("exists($.a[*] ? (!(@.b == 1)))", C_NOT_IN_FILTER, 17),
                ("exists($.a[*] ? (@.b != 1))", C_NE_IN_FILTER, 21),
                ("exists($.a[*] ? (exists(@.b)))", C_EXISTS_IN_FILTER, 17),
                ("exists($.a[*] ? ($.b == 1))", C_DOLLAR_IN_FILTER, 17),
                ("$.v == $x.y", C_VARIABLE_PATH, 9),
                ("$.tags[*] < 1", C_ELEMENTS_THEMSELVES, 10),
                (
                    "exists($.contacts[*] ? (@ > 1 && @.calls < 2))",
                    C_ELEMENTS_THEMSELVES,
                    24,
                ),
                (
                    "exists($.contacts[*] ? (@ == 1 && @.calls < 2))",
                    C_WHOLE_ELEMENT,
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
                ("", C_TEXT, 0),
                ("$.a == 1 &&", C_TEXT, 11),
                ("$.a = 1", C_TEXT, 4),
                ("$.a === 1", C_TEXT, 6),
                ("$.a > 1 > 2", C_TRAILING, 8),
                ("$.a == 1 2", C_TRAILING, 9),
                ("($.a == 1) is unknown", C_TRAILING, 11),
                ("!$.a == 1", C_TEXT, 1),
                ("!!($.a == 1)", C_TEXT, 1),
                ("($.a == 1", C_TEXT, 9),
                ("$.a == 01", C_NUMBER, 7),
                ("$.a == 1.", C_NUMBER, 7),
                ("$.a == 1e", C_NUMBER, 7),
                ("$.a == .5", C_TEXT, 7),
                ("$.a == 'x'", C_TEXT, 7),
                (r#"$.a == "x"#, C_STRING, 7),
                (r#"$."a == 1"#, C_STRING, 2),
                ("$.a == TRUE", C_TEXT, 7),
                ("$.1a == 1", C_TEXT, 2),
                ("$. == 1", C_TEXT, 3),
                ("$.a == 1 /* open", C_TEXT, 9),
                ("exists $.a", C_TEXT, 7),
                ("$.a == $1", C_TEXT, 8),
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
                ("$.a[2] == 1", (JsonPathPosition, C_POSITION, 3)),
                ("exists($.a[ 0 ])", (JsonPathPosition, C_POSITION, 10)),
                (
                    "$.a[*] != 1",
                    (JsonPredicateNotEqualAtWildcard, C_NOT_EQUAL, 7),
                ),
                (
                    "$.a[*].b != null",
                    (JsonPredicateNotEqualAtWildcard, C_NOT_EQUAL, 9),
                ),
                (
                    "exists($.a ? (@ == 1))",
                    (JsonPathNoWildcard, C_FILTER_WILDCARD, 7),
                ),
                (
                    "exists($.a[*] ? (@.b[*] == 1))",
                    (JsonPathWildcard, C_MEMBER_WILDCARD, 17),
                ),
                (
                    deep.as_str(),
                    (JsonPredicateTooDeep, C_NESTING, MAX_NESTING + 1),
                ),
                (long.as_str(), (JsonPredicateTooDeep, C_NESTING, 0)),
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
                (JsonPredicateTooDeep, C_NESTING, 7),
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
                (JsonPredicateTooDeep, C_NESTING, 7),
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
                (JsonPredicateTooDeep, C_NESTING, 0),
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
