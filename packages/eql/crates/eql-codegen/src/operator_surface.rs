//! The generated operator surface.

/// The closed set of SQL operator symbols the generator knows about. Modelling
/// the symbol as an enum (rather than a bare `&'static str`) makes the two
/// methods that diverge on it — `wrapper_function_name` and `body_operator` —
/// **exhaustive, compiler-checked matches**: adding a new operator forces a
/// compile error at those match sites until the author explicitly classifies
/// it, rather than silently inheriting a `_ =>` default.
///
/// `as_str` is the single source of truth for each variant's SQL text.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum OpSymbol {
    /// `=`
    Eq,
    /// `<>`
    Neq,
    /// `<`
    Lt,
    /// `<=`
    Lte,
    /// `>`
    Gt,
    /// `>=`
    Gte,
    /// `@>`
    Contains,
    /// `<@`
    ContainedBy,
    /// `->`
    Arrow,
    /// `->>`
    ArrowArrow,
    /// `?`
    Question,
    /// `?|`
    QuestionPipe,
    /// `?&`
    QuestionAmp,
    /// `@?`
    AtQuestion,
    /// `@@`
    Match,
    /// `#>`
    HashArrow,
    /// `#>>`
    HashArrowArrow,
    /// `-`
    Minus,
    /// `#-`
    HashMinus,
    /// `||`
    Concat,
}

impl OpSymbol {
    /// The SQL operator text for this symbol (e.g. `OpSymbol::Eq => "="`). The
    /// single source of truth for the string form — every raw-string use site
    /// (SQL rendering, snapshot output, lookups) goes through here.
    pub const fn as_str(&self) -> &'static str {
        match self {
            OpSymbol::Eq => "=",
            OpSymbol::Neq => "<>",
            OpSymbol::Lt => "<",
            OpSymbol::Lte => "<=",
            OpSymbol::Gt => ">",
            OpSymbol::Gte => ">=",
            OpSymbol::Contains => "@>",
            OpSymbol::ContainedBy => "<@",
            OpSymbol::Arrow => "->",
            OpSymbol::ArrowArrow => "->>",
            OpSymbol::Question => "?",
            OpSymbol::QuestionPipe => "?|",
            OpSymbol::QuestionAmp => "?&",
            OpSymbol::AtQuestion => "@?",
            OpSymbol::Match => "@@",
            OpSymbol::HashArrow => "#>",
            OpSymbol::HashArrowArrow => "#>>",
            OpSymbol::Minus => "-",
            OpSymbol::HashMinus => "#-",
            OpSymbol::Concat => "||",
        }
    }
}

/// One operator in the generated surface.
#[derive(Clone, Copy)]
pub struct Operator {
    pub symbol: OpSymbol,
    pub function_name: &'static str,
    pub signatures: &'static [OperatorSignature],
    pub metadata: OperatorMetadata,
}

/// Optional `CREATE OPERATOR` planner metadata. Pure data — whether it is
/// emitted is a per-domain decision (supported operators only), not a property
/// of the operator's category.
#[derive(Clone, Copy)]
pub struct OperatorMetadata {
    pub restrict: Option<&'static str>,
    pub join: Option<&'static str>,
    pub commutator: Option<&'static str>,
    pub negator: Option<&'static str>,
}

impl OperatorMetadata {
    /// Metadata with no planner hints — the common case for operators that carry
    /// no commutator/negator/selectivity estimators.
    pub const fn none() -> Self {
        Self {
            restrict: None,
            join: None,
            commutator: None,
            negator: None,
        }
    }

    /// Render the `CREATE OPERATOR` metadata clause, or `None` when no hint is
    /// present (e.g. the path-selector operators, which carry no metadata).
    ///
    /// The emission order (COMMUTATOR, NEGATOR, RESTRICT, JOIN) is **load-bearing
    /// for the reference byte-match** — reordering these blocks changes generated
    /// SQL and breaks the parity gate. Keep it fixed regardless of struct field
    /// order.
    pub fn render(self) -> Option<String> {
        let mut extras = Vec::new();
        if let Some(c) = self.commutator {
            extras.push(format!("COMMUTATOR = {c}"));
        }
        if let Some(n) = self.negator {
            extras.push(format!("NEGATOR = {n}"));
        }
        if let Some(r) = self.restrict {
            extras.push(format!("RESTRICT = {r}"));
        }
        if let Some(j) = self.join {
            extras.push(format!("JOIN = {j}"));
        }
        (!extras.is_empty()).then(|| extras.join(", "))
    }
}

/// A type position in a PostgreSQL operator overload. `Domain` renders to the
/// concrete encrypted domain being generated; every other slot renders to a
/// fixed PostgreSQL type name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TypeSlot {
    Domain,
    Jsonb,
    Text,
    Integer,
    TextArray,
    Jsonpath,
    Boolean,
}

impl TypeSlot {
    fn render(self, dom: &str) -> String {
        match self {
            TypeSlot::Domain => dom.to_string(),
            TypeSlot::Jsonb => "jsonb".to_string(),
            TypeSlot::Text => "text".to_string(),
            TypeSlot::Integer => "integer".to_string(),
            TypeSlot::TextArray => "text[]".to_string(),
            TypeSlot::Jsonpath => "jsonpath".to_string(),
            TypeSlot::Boolean => "boolean".to_string(),
        }
    }
}

/// One PostgreSQL-shaped operator overload: left/right argument slots and the
/// return slot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OperatorSignature {
    pub left: TypeSlot,
    pub right: TypeSlot,
    pub returns: TypeSlot,
    /// When true this overload is ALWAYS rendered as a blocker, even on a domain
    /// whose terms otherwise support the operator's symbol. The only user is the
    /// `@@` `(domain, jsonpath)` native-jsonb-predicate overload: `@@` is the
    /// SUPPORTED bloom fuzzy-match operator on match domains for its symmetric
    /// domain/jsonb overloads, but its jsonpath overload must keep raising (the
    /// "no silent native jsonb ops" guarantee) on every domain including the
    /// match domains. Normal operators leave this `false`.
    pub blocker_only: bool,
}

/// An `OperatorSignature` with every slot resolved to a concrete SQL type name.
pub struct RenderedSignature {
    pub left: String,
    pub right: String,
    pub returns: String,
}

impl OperatorSignature {
    pub fn render(self, dom: &str) -> RenderedSignature {
        RenderedSignature {
            left: self.left.render(dom),
            right: self.right.render(dom),
            returns: self.returns.render(dom),
        }
    }
}

/// Terse constructor for the static signature tables below.
const fn sig(left: TypeSlot, right: TypeSlot, returns: TypeSlot) -> OperatorSignature {
    OperatorSignature {
        left,
        right,
        returns,
        blocker_only: false,
    }
}

/// Constructor for an always-blocked overload (see `OperatorSignature::blocker_only`).
const fn sig_blocker(left: TypeSlot, right: TypeSlot, returns: TypeSlot) -> OperatorSignature {
    OperatorSignature {
        left,
        right,
        returns,
        blocker_only: true,
    }
}

/// Symmetric boolean overloads (`domain`/`jsonb` convenience pairs), shared by
/// `=`, `<>`, `<`, `<=`, `>`, `>=`, `@>`, `<@`.
const BOOL_SYMMETRIC_SIGNATURES: &[OperatorSignature] = &[
    sig(TypeSlot::Domain, TypeSlot::Domain, TypeSlot::Boolean),
    sig(TypeSlot::Domain, TypeSlot::Jsonb, TypeSlot::Boolean),
    sig(TypeSlot::Jsonb, TypeSlot::Domain, TypeSlot::Boolean),
];

/// `->` path-selector overloads (returns the domain).
const ARROW_SIGNATURES: &[OperatorSignature] = &[
    sig(TypeSlot::Domain, TypeSlot::Text, TypeSlot::Domain),
    sig(TypeSlot::Domain, TypeSlot::Integer, TypeSlot::Domain),
    sig(TypeSlot::Jsonb, TypeSlot::Domain, TypeSlot::Domain),
];

/// `->>` path-selector overloads (returns text).
const ARROW_TEXT_SIGNATURES: &[OperatorSignature] = &[
    sig(TypeSlot::Domain, TypeSlot::Text, TypeSlot::Text),
    sig(TypeSlot::Domain, TypeSlot::Integer, TypeSlot::Text),
    sig(TypeSlot::Jsonb, TypeSlot::Domain, TypeSlot::Text),
];

/// `?` key-existence overload.
const HAS_KEY_SIGNATURES: &[OperatorSignature] =
    &[sig(TypeSlot::Domain, TypeSlot::Text, TypeSlot::Boolean)];

/// `?|` / `?&` any/all-keys overloads.
const HAS_ANY_KEYS_SIGNATURES: &[OperatorSignature] = &[sig(
    TypeSlot::Domain,
    TypeSlot::TextArray,
    TypeSlot::Boolean,
)];

/// `@?` jsonpath-predicate overload (also the shape `@@` blocks on non-match
/// domains — see `MATCH_SIGNATURES`).
const JSONPATH_SIGNATURES: &[OperatorSignature] =
    &[sig(TypeSlot::Domain, TypeSlot::Jsonpath, TypeSlot::Boolean)];

/// `@@` bloom fuzzy-match overloads: the symmetric domain/jsonb match shapes
/// (SUPPORTED on Bloom-carrying domains, backed by `eql_v3.matches`), plus the
/// native-jsonb `(domain, jsonpath)` predicate overload marked `blocker_only`
/// so it keeps raising on every domain (including match domains). On non-Bloom
/// domains all four render as blockers, exactly as `@>`/`<@` do for a domain
/// that does not support containment.
const MATCH_SIGNATURES: &[OperatorSignature] = &[
    sig(TypeSlot::Domain, TypeSlot::Domain, TypeSlot::Boolean),
    sig(TypeSlot::Domain, TypeSlot::Jsonb, TypeSlot::Boolean),
    sig(TypeSlot::Jsonb, TypeSlot::Domain, TypeSlot::Boolean),
    sig_blocker(TypeSlot::Domain, TypeSlot::Jsonpath, TypeSlot::Boolean),
];

/// `#>` path-extract overload (returns jsonb).
const PATH_EXTRACT_JSONB_SIGNATURES: &[OperatorSignature] =
    &[sig(TypeSlot::Domain, TypeSlot::TextArray, TypeSlot::Jsonb)];

/// `#>>` path-extract overload (returns text).
const PATH_EXTRACT_TEXT_SIGNATURES: &[OperatorSignature] =
    &[sig(TypeSlot::Domain, TypeSlot::TextArray, TypeSlot::Text)];

/// `-` delete-key overloads.
const DELETE_SIGNATURES: &[OperatorSignature] = &[
    sig(TypeSlot::Domain, TypeSlot::Text, TypeSlot::Jsonb),
    sig(TypeSlot::Domain, TypeSlot::Integer, TypeSlot::Jsonb),
    sig(TypeSlot::Domain, TypeSlot::TextArray, TypeSlot::Jsonb),
];

/// `#-` delete-path overload.
const DELETE_PATH_SIGNATURES: &[OperatorSignature] =
    &[sig(TypeSlot::Domain, TypeSlot::TextArray, TypeSlot::Jsonb)];

/// `||` concatenation overloads (`domain`/`jsonb` convenience pairs).
const CONCAT_SIGNATURES: &[OperatorSignature] = &[
    sig(TypeSlot::Domain, TypeSlot::Domain, TypeSlot::Jsonb),
    sig(TypeSlot::Domain, TypeSlot::Jsonb, TypeSlot::Jsonb),
    sig(TypeSlot::Jsonb, TypeSlot::Domain, TypeSlot::Jsonb),
];

/// Look up the operator metadata for a symbol. Panics on an unknown symbol —
/// the generator only ever passes catalog symbols, matching Python's KeyError.
pub fn operator(symbol: &str) -> Operator {
    OPERATORS
        .iter()
        .copied()
        .find(|o| o.symbol.as_str() == symbol)
        .unwrap_or_else(|| panic!("unknown operator symbol: {symbol}"))
}

/// The generated SQL function name for an operator symbol (e.g. `eq`, `"->"`).
pub fn operator_function_name(symbol: &str) -> &'static str {
    operator(symbol).function_name
}

impl Operator {
    /// True for the native-jsonb operators that every encrypted domain
    /// generates as BLOCKERS: those that are neither comparison
    /// (`=`/`<>`/`<`/`<=`/`>`/`>=`), nor containment (`@>`/`<@`), nor
    /// path-selectors (`->`/`->>`). Derived by exclusion so a 21st operator
    /// added to `OPERATORS` is automatically classified — no literal list to
    /// drift out of sync.
    pub fn is_native_jsonb_blocker(&self) -> bool {
        const COMPARISON: &[&str] = &["=", "<>", "<", "<=", ">", ">="];
        const CONTAINMENT: &[&str] = &["@>", "<@"];
        const PATH_SELECTOR: &[&str] = &["->", "->>"];
        let symbol = self.symbol.as_str();
        !COMPARISON.contains(&symbol)
            && !CONTAINMENT.contains(&symbol)
            && !PATH_SELECTOR.contains(&symbol)
    }

    /// The name of the SUPPORTED comparison-wrapper function for this operator
    /// (the `eql_v3.<name>` public wrapper). Equal to `function_name` for every
    /// operator except `@@`, whose supported form is the bloom fuzzy-match
    /// `eql_v3.matches` while its blocked `(domain, jsonpath)` overload keeps the
    /// blocker name `eql_v3_internal."@@"`. The blocker path always uses
    /// `function_name`; only the wrapper/supported path calls this.
    pub fn wrapper_function_name(&self) -> &'static str {
        // Exhaustive on purpose: no `_ =>` fallthrough. A future operator that
        // needs a divergent wrapper name must be classified here (compile error
        // until it is), rather than silently inheriting `function_name`.
        match self.symbol {
            OpSymbol::Match => "matches",
            OpSymbol::Eq
            | OpSymbol::Neq
            | OpSymbol::Lt
            | OpSymbol::Lte
            | OpSymbol::Gt
            | OpSymbol::Gte
            | OpSymbol::Contains
            | OpSymbol::ContainedBy
            | OpSymbol::Arrow
            | OpSymbol::ArrowArrow
            | OpSymbol::Question
            | OpSymbol::QuestionPipe
            | OpSymbol::QuestionAmp
            | OpSymbol::AtQuestion
            | OpSymbol::HashArrow
            | OpSymbol::HashArrowArrow
            | OpSymbol::Minus
            | OpSymbol::HashMinus
            | OpSymbol::Concat => self.function_name,
        }
    }

    /// The SQL operator used INSIDE the wrapper body
    /// (`extractor(a) <body_operator> extractor(b)`). Equal to `symbol` for every
    /// operator except `@@`, whose body performs bloom array-containment `@>` on
    /// the extracted `eql_v3_internal.bloom_filter` (`smallint[]`) terms. So the
    /// public `@@` fuzzy-match operator reduces, through inlining, to exactly the
    /// GIN-indexable `match_term(col) @> match_term(needle)` expression the former
    /// `contains` wrapper produced — no new operator on the SEM bloom_filter type,
    /// and the proven single-level inline to the array `@>` GIN opclass is kept.
    pub fn body_operator(&self) -> &'static str {
        // Exhaustive on purpose: no `_ =>` fallthrough. A future operator whose
        // wrapper body must use a different SQL operator than its own symbol
        // must be classified here (compile error until it is).
        match self.symbol {
            OpSymbol::Match => "@>",
            OpSymbol::Eq
            | OpSymbol::Neq
            | OpSymbol::Lt
            | OpSymbol::Lte
            | OpSymbol::Gt
            | OpSymbol::Gte
            | OpSymbol::Contains
            | OpSymbol::ContainedBy
            | OpSymbol::Arrow
            | OpSymbol::ArrowArrow
            | OpSymbol::Question
            | OpSymbol::QuestionPipe
            | OpSymbol::QuestionAmp
            | OpSymbol::AtQuestion
            | OpSymbol::HashArrow
            | OpSymbol::HashArrowArrow
            | OpSymbol::Minus
            | OpSymbol::HashMinus
            | OpSymbol::Concat => self.symbol.as_str(),
        }
    }

    /// Whether the wrapper body must carry the empty-needle guard.
    ///
    /// True only for `@@`, whose body is bloom array-containment (`@>`). Bare
    /// `match_term(a) @> match_term(b)` is vacuously TRUE whenever the needle
    /// bloom `b` is empty (`{}` is `@>` by everything), so a query term with no
    /// n-gram tokens would match every row. The wrapper renderer appends
    /// `AND (cardinality(match_term(b)) > 0 OR cardinality(match_term(a)) = 0)`,
    /// giving `LIKE`-shaped semantics: an empty needle matches only a value whose
    /// own bloom is also empty. The top-level `@>` conjunct is preserved so the
    /// functional GIN index on `match_term(col)` still engages; for a non-empty
    /// needle the guard folds to a constant `TRUE` and drops out at plan time.
    ///
    /// Every other operator's body is a single comparison with no such
    /// degenerate-empty case, so this is exhaustively `Match`-only.
    ///
    /// The guarded wrapper is rendered **without `STRICT`** (the bare wrappers
    /// keep it). PostgreSQL refuses to inline a `STRICT` SQL function whose body
    /// contains non-strict constructs, and the guard introduces top-level
    /// `AND`/`OR` (both non-strict: `false AND NULL` is `false`, `true OR NULL`
    /// is `true`). A `STRICT` guarded wrapper would therefore stop inlining, and
    /// `col @@ needle` would no longer fold to `match_term(col) @> match_term(
    /// needle)` — losing the functional GIN index. The body propagates `NULL`
    /// on a `NULL` operand on its own (`NULL @> y` is `NULL`, and the guard's
    /// `OR`/`AND` carry that `NULL` through), so dropping `STRICT` preserves the
    /// wrapper's NULL semantics while restoring inlinability.
    pub fn needs_empty_bloom_guard(&self) -> bool {
        matches!(self.symbol, OpSymbol::Match)
    }
}

/// The native-jsonb operator symbols that every encrypted domain blocks, in
/// `OPERATORS` order. Source of truth for the matrix's native-jsonb-blocker
/// arm — the arm asserts its hand-written RHS map's keys equal this set.
pub fn native_jsonb_blocker_symbols() -> Vec<&'static str> {
    OPERATORS
        .iter()
        .filter(|o| o.is_native_jsonb_blocker())
        .map(|o| o.symbol.as_str())
        .collect()
}

/// Comparison-operator metadata (commutator/negator/selectivity estimators).
const fn cmp_metadata(
    restrict: &'static str,
    join: &'static str,
    commutator: &'static str,
    negator: &'static str,
) -> OperatorMetadata {
    OperatorMetadata {
        restrict: Some(restrict),
        join: Some(join),
        commutator: Some(commutator),
        negator: Some(negator),
    }
}

/// Containment-operator metadata (`@>` / `<@`): commutator is the mirror
/// operator, no negator (a non-containment is not another listed operator),
/// containment selectivity estimators.
const fn containment_metadata(commutator: &'static str) -> OperatorMetadata {
    OperatorMetadata {
        restrict: Some("contsel"),
        join: Some("contjoinsel"),
        commutator: Some(commutator),
        negator: None,
    }
}

/// Match-operator metadata (`@@`): the bloom fuzzy-match is array containment
/// under the hood, so it reuses the containment selectivity estimators, but it
/// is a single directional operator with no reverse — hence no commutator and
/// no negator.
const fn match_metadata() -> OperatorMetadata {
    OperatorMetadata {
        restrict: Some("contsel"),
        join: Some("contjoinsel"),
        commutator: None,
        negator: None,
    }
}

/// The 20-operator catalog. Order is: comparison operators, then path-selector
/// operators, then the remaining native jsonb operators.
pub const OPERATORS: &[Operator] = &[
    Operator {
        symbol: OpSymbol::Eq,
        function_name: "eq",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: cmp_metadata("eqsel", "eqjoinsel", "=", "<>"),
    },
    Operator {
        symbol: OpSymbol::Neq,
        function_name: "neq",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: cmp_metadata("neqsel", "neqjoinsel", "<>", "="),
    },
    Operator {
        symbol: OpSymbol::Lt,
        function_name: "lt",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: cmp_metadata("scalarltsel", "scalarltjoinsel", ">", ">="),
    },
    Operator {
        symbol: OpSymbol::Lte,
        function_name: "lte",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: cmp_metadata("scalarlesel", "scalarlejoinsel", ">=", ">"),
    },
    Operator {
        symbol: OpSymbol::Gt,
        function_name: "gt",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: cmp_metadata("scalargtsel", "scalargtjoinsel", "<", "<="),
    },
    Operator {
        symbol: OpSymbol::Gte,
        function_name: "gte",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: cmp_metadata("scalargesel", "scalargejoinsel", "<=", "<"),
    },
    Operator {
        symbol: OpSymbol::Contains,
        function_name: "contains",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: containment_metadata("<@"),
    },
    Operator {
        symbol: OpSymbol::ContainedBy,
        function_name: "contained_by",
        signatures: BOOL_SYMMETRIC_SIGNATURES,
        metadata: containment_metadata("@>"),
    },
    Operator {
        symbol: OpSymbol::Arrow,
        function_name: "\"->\"",
        signatures: ARROW_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::ArrowArrow,
        function_name: "\"->>\"",
        signatures: ARROW_TEXT_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::Question,
        function_name: "\"?\"",
        signatures: HAS_KEY_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::QuestionPipe,
        function_name: "\"?|\"",
        signatures: HAS_ANY_KEYS_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::QuestionAmp,
        function_name: "\"?&\"",
        signatures: HAS_ANY_KEYS_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::AtQuestion,
        function_name: "\"@?\"",
        signatures: JSONPATH_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::Match,
        function_name: "\"@@\"",
        signatures: MATCH_SIGNATURES,
        metadata: match_metadata(),
    },
    Operator {
        symbol: OpSymbol::HashArrow,
        function_name: "\"#>\"",
        signatures: PATH_EXTRACT_JSONB_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::HashArrowArrow,
        function_name: "\"#>>\"",
        signatures: PATH_EXTRACT_TEXT_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::Minus,
        function_name: "\"-\"",
        signatures: DELETE_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::HashMinus,
        function_name: "\"#-\"",
        signatures: DELETE_PATH_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
    Operator {
        symbol: OpSymbol::Concat,
        function_name: "\"||\"",
        signatures: CONCAT_SIGNATURES,
        metadata: OperatorMetadata::none(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered_signatures(op: &str) -> Vec<(String, String, String)> {
        operator(op)
            .signatures
            .iter()
            .map(|sig| sig.render("public.eql_v3_integer_ord"))
            .map(|sig| (sig.left, sig.right, sig.returns))
            .collect()
    }

    #[test]
    fn signature_slots_render_for_domain() {
        let sig = OperatorSignature {
            left: TypeSlot::Domain,
            right: TypeSlot::Text,
            returns: TypeSlot::Boolean,
            blocker_only: false,
        };
        let rendered = sig.render("public.eql_v3_integer_eq");
        assert_eq!(rendered.left, "public.eql_v3_integer_eq");
        assert_eq!(rendered.right, "text");
        assert_eq!(rendered.returns, "boolean");
    }

    #[test]
    fn operator_catalog_carries_postgres_signatures() {
        let arrow = operator("->");
        let rendered: Vec<_> = arrow
            .signatures
            .iter()
            .map(|sig| sig.render("public.eql_v3_integer"))
            .map(|sig| (sig.left, sig.right, sig.returns))
            .collect();
        assert_eq!(
            rendered,
            vec![
                (
                    "public.eql_v3_integer".to_string(),
                    "text".to_string(),
                    "public.eql_v3_integer".to_string()
                ),
                (
                    "public.eql_v3_integer".to_string(),
                    "integer".to_string(),
                    "public.eql_v3_integer".to_string()
                ),
                (
                    "jsonb".to_string(),
                    "public.eql_v3_integer".to_string(),
                    "public.eql_v3_integer".to_string()
                ),
            ]
        );
    }

    #[test]
    fn equality_signatures_match_existing_symmetric_shapes() {
        assert_eq!(
            rendered_signatures("="),
            vec![
                (
                    "public.eql_v3_integer_ord".into(),
                    "public.eql_v3_integer_ord".into(),
                    "boolean".into()
                ),
                (
                    "public.eql_v3_integer_ord".into(),
                    "jsonb".into(),
                    "boolean".into()
                ),
                (
                    "jsonb".into(),
                    "public.eql_v3_integer_ord".into(),
                    "boolean".into()
                ),
            ]
        );
    }

    #[test]
    fn native_jsonb_signatures_match_existing_operator_shapes() {
        assert_eq!(
            rendered_signatures("||"),
            vec![
                (
                    "public.eql_v3_integer_ord".into(),
                    "public.eql_v3_integer_ord".into(),
                    "jsonb".into()
                ),
                (
                    "public.eql_v3_integer_ord".into(),
                    "jsonb".into(),
                    "jsonb".into()
                ),
                (
                    "jsonb".into(),
                    "public.eql_v3_integer_ord".into(),
                    "jsonb".into()
                ),
            ]
        );
        assert_eq!(
            rendered_signatures("?|"),
            vec![(
                "public.eql_v3_integer_ord".into(),
                "text[]".into(),
                "boolean".into()
            )]
        );
    }

    #[test]
    fn jsonpath_and_text_array_signatures_render() {
        // `@?` carries the jsonpath slot and `#>`/`#>>` carry the text[] slot —
        // the slot kinds not asserted by the symmetric/arrow signature tests.
        assert_eq!(
            rendered_signatures("@?"),
            vec![(
                "public.eql_v3_integer_ord".into(),
                "jsonpath".into(),
                "boolean".into()
            )]
        );
        assert_eq!(
            rendered_signatures("#>"),
            vec![(
                "public.eql_v3_integer_ord".into(),
                "text[]".into(),
                "jsonb".into()
            )]
        );
        assert_eq!(
            rendered_signatures("#>>"),
            vec![(
                "public.eql_v3_integer_ord".into(),
                "text[]".into(),
                "text".into()
            )]
        );
    }

    #[test]
    fn twenty_operators_total() {
        assert_eq!(OPERATORS.len(), 20);
    }

    #[test]
    #[should_panic(expected = "unknown operator symbol")]
    fn operator_panics_on_unknown_symbol() {
        // The generator only ever passes catalog symbols; an unknown symbol is a
        // programming error and must fail loudly rather than silently no-op.
        let _ = operator("~~");
    }

    #[test]
    fn every_operator_has_signatures() {
        assert!(
            OPERATORS.iter().all(|o| !o.signatures.is_empty()),
            "every catalog operator must declare at least one signature"
        );
    }

    #[test]
    fn no_like_operators() {
        assert!(OPERATORS
            .iter()
            .all(|o| o.symbol.as_str() != "~~" && o.symbol.as_str() != "~~*"));
    }

    #[test]
    fn function_names() {
        assert_eq!(operator_function_name("="), "eq");
        assert_eq!(operator_function_name("<>"), "neq");
        assert_eq!(operator_function_name("<"), "lt");
        assert_eq!(operator_function_name("<="), "lte");
        assert_eq!(operator_function_name(">"), "gt");
        assert_eq!(operator_function_name(">="), "gte");
        assert_eq!(operator_function_name("@>"), "contains");
        assert_eq!(operator_function_name("<@"), "contained_by");
        assert_eq!(operator_function_name("->"), "\"->\"");
        assert_eq!(operator_function_name("->>"), "\"->>\"");
        assert_eq!(operator_function_name("?"), "\"?\"");
        assert_eq!(operator_function_name("?|"), "\"?|\"");
        assert_eq!(operator_function_name("?&"), "\"?&\"");
        assert_eq!(operator_function_name("@?"), "\"@?\"");
        assert_eq!(operator_function_name("@@"), "\"@@\"");
        assert_eq!(operator_function_name("#>"), "\"#>\"");
        assert_eq!(operator_function_name("#>>"), "\"#>>\"");
        assert_eq!(operator_function_name("-"), "\"-\"");
        assert_eq!(operator_function_name("#-"), "\"#-\"");
        assert_eq!(operator_function_name("||"), "\"||\"");
    }

    #[test]
    fn selectivity_estimators() {
        assert_eq!(operator("=").metadata.restrict, Some("eqsel"));
        assert_eq!(operator("=").metadata.join, Some("eqjoinsel"));
        assert_eq!(operator("<>").metadata.restrict, Some("neqsel"));
        assert_eq!(operator("<").metadata.restrict, Some("scalarltsel"));
        assert_eq!(operator("<=").metadata.restrict, Some("scalarlesel"));
        assert_eq!(operator(">").metadata.restrict, Some("scalargtsel"));
        assert_eq!(operator(">=").metadata.restrict, Some("scalargesel"));
    }

    #[test]
    fn negators_and_commutators() {
        assert_eq!(operator("=").metadata.negator, Some("<>"));
        assert_eq!(operator("<>").metadata.negator, Some("="));
        assert_eq!(operator("<").metadata.commutator, Some(">"));
        assert_eq!(operator("<").metadata.negator, Some(">="));
        assert_eq!(operator(">=").metadata.commutator, Some("<="));
    }

    #[test]
    fn metadata_renders_only_when_present() {
        assert_eq!(
            operator("=").metadata.render().unwrap(),
            "COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel"
        );
        assert_eq!(operator("->").metadata.render(), None);
        // `@>`/`<@` now carry containment metadata (no negator).
        assert_eq!(
            operator("@>").metadata.render().unwrap(),
            "COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel"
        );
    }

    #[test]
    fn containment_operators_have_containment_metadata() {
        let c = operator("@>");
        assert_eq!(c.metadata.commutator, Some("<@"));
        assert_eq!(c.metadata.restrict, Some("contsel"));
        assert_eq!(c.metadata.join, Some("contjoinsel"));
        assert_eq!(c.metadata.negator, None);
        let cb = operator("<@");
        assert_eq!(cb.metadata.commutator, Some("@>"));
        assert_eq!(cb.metadata.restrict, Some("contsel"));
        assert_eq!(cb.metadata.join, Some("contjoinsel"));
        assert_eq!(cb.metadata.negator, None);
    }

    #[test]
    fn catalog_symbols_match_expected_order() {
        let keys: Vec<&str> = OPERATORS.iter().map(|o| o.symbol.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "=", "<>", "<", "<=", ">", ">=", "@>", "<@", "->", "->>", "?", "?|", "?&", "@?",
                "@@", "#>", "#>>", "-", "#-", "||"
            ]
        );
    }

    #[test]
    fn match_operator_carries_symmetric_and_blocker_only_signatures() {
        // `@@` is the bloom fuzzy-match operator: three symmetric match overloads
        // plus the always-blocked `(domain, jsonpath)` native-jsonb predicate.
        let at_at = operator("@@");
        assert_eq!(at_at.signatures.len(), 4);
        let symmetric: Vec<_> = at_at
            .signatures
            .iter()
            .filter(|s| !s.blocker_only)
            .map(|s| (s.left, s.right))
            .collect();
        assert_eq!(
            symmetric,
            vec![
                (TypeSlot::Domain, TypeSlot::Domain),
                (TypeSlot::Domain, TypeSlot::Jsonb),
                (TypeSlot::Jsonb, TypeSlot::Domain),
            ]
        );
        let blocker_only: Vec<_> = at_at
            .signatures
            .iter()
            .filter(|s| s.blocker_only)
            .map(|s| (s.left, s.right))
            .collect();
        assert_eq!(blocker_only, vec![(TypeSlot::Domain, TypeSlot::Jsonpath)]);
    }

    #[test]
    fn wrapper_function_name_overrides_only_for_match() {
        // The supported wrapper for `@@` is `matches`; its blocker name stays
        // `"@@"`. Every other operator's wrapper and blocker names coincide.
        assert_eq!(operator("@@").wrapper_function_name(), "matches");
        assert_eq!(operator("@@").function_name, "\"@@\"");
        assert_eq!(operator("=").wrapper_function_name(), "eq");
        assert_eq!(operator("@>").wrapper_function_name(), "contains");
    }

    #[test]
    fn native_jsonb_blocker_symbols_are_the_residual_ten() {
        // The residual after removing the 6 comparison + 2 containment + 2
        // path-selector ops from the 20-operator catalog. If a 21st operator is
        // added, classify it (comparison/containment/path-selector/native) and
        // update this list and the matrix arm's RHS map together.
        assert_eq!(
            native_jsonb_blocker_symbols(),
            vec!["?", "?|", "?&", "@?", "@@", "#>", "#>>", "-", "#-", "||"],
        );
    }
}
