//! minijinja environment + serde context structs + relocated logic helpers.

use crate::consts::*;
use crate::operator_surface::Operator;
use eql_domains::{Domain, Term};

/// Build the minijinja environment with the embedded templates: one whole-file
/// template per output file (`types`/`functions`/`operators`/`aggregates`) plus
/// the per-kind function-body partials that `functions.sql` dynamically
/// `{% include %}`s. Templates are compiled in via `include_str!` — no runtime
/// file IO.
pub fn environment() -> minijinja::Environment<'static> {
    let mut env = minijinja::Environment::new();
    // Preserve each template file's trailing newline so generated SQL files end
    // with one (minijinja strips it by default).
    env.set_keep_trailing_newline(true);
    env.add_template("types.sql", include_str!("../templates/types.sql.j2"))
        .expect("types.sql template");
    env.add_template(
        "query_types.sql",
        include_str!("../templates/query_types.sql.j2"),
    )
    .expect("query_types.sql template");
    env.add_template(
        "functions.sql",
        include_str!("../templates/functions.sql.j2"),
    )
    .expect("functions.sql template");
    // Per-kind function bodies, dynamically `{% include %}`d by the parent
    // `functions.sql` template based on each entry's `kind` tag
    // (Extractor/Wrapper/Unsupported -> extractor/wrapper/unsupported).
    env.add_template(
        "functions/extractor.sql.j2",
        include_str!("../templates/functions/extractor.sql.j2"),
    )
    .expect("functions/extractor.sql.j2 template");
    env.add_template(
        "functions/wrapper.sql.j2",
        include_str!("../templates/functions/wrapper.sql.j2"),
    )
    .expect("functions/wrapper.sql.j2 template");
    env.add_template(
        "functions/unsupported.sql.j2",
        include_str!("../templates/functions/unsupported.sql.j2"),
    )
    .expect("functions/unsupported.sql.j2 template");
    env.add_template(
        "operators.sql",
        include_str!("../templates/operators.sql.j2"),
    )
    .expect("operators.sql template");
    env.add_template(
        "aggregates.sql",
        include_str!("../templates/aggregates.sql.j2"),
    )
    .expect("aggregates.sql template");
    env.add_template(
        "ore_fallback.sql",
        include_str!("../templates/ore_fallback.sql.j2"),
    )
    .expect("ore_fallback.sql template");
    env.add_global("schema", SCHEMA);
    env.add_global("internal_schema", INTERNAL_SCHEMA);
    env
}

/// One idempotent CREATE DOMAIN block, with SQL-required values precomputed.
#[derive(serde::Serialize)]
pub struct DomainBlock {
    pub typname: String,   // sql_str-escaped typname, e.g. eql_v3_integer_ord_ore
    pub name: String,      // raw typname (unescaped), e.g. eql_v3_integer_ord_ore
    pub keys: Vec<String>, // ordered, sql_str-escaped key tokens (envelope + ciphertext + term keys)
    // sql_str-escaped keys whose payload must be a non-empty array (the ORE term
    // `ob`). Derived from the domain's terms exactly like `keys`, so the template
    // stays term-agnostic — it renders a non-empty-array CHECK per key without
    // hardcoding `ob`. Empty for non-ORE domains. See issue #262.
    pub nonempty_array_keys: Vec<String>,
    // sql_str-escaped keys the payload must NOT carry. Empty for storage domains;
    // `['c']` for a query-operand twin, whose CHECK forbids the ciphertext (a
    // query operand is index-terms-only). The template renders a
    // `NOT (VALUE ? k)` clause per key.
    pub forbidden_keys: Vec<String>,
    // sql_str-escaped one-line human description rendered as `COMMENT ON DOMAIN`.
    // Capability text is derived from the domain's terms (via
    // `Term::operators_for_terms`), so it can't drift from the generated CHECK /
    // operators. Surfaced by `\dD`, `obj_description`, and tooling that reads
    // pg_type comments (e.g. Supabase's `types` introspection).
    pub comment: String,
}

/// Concise capability phrase from a domain's operator set — `equality`,
/// `ordering`, `containment` (joined), or `storage only` when term-less. Derived
/// from `operators_for_terms` so it tracks the generated surface; kept short so
/// the `COMMENT ON DOMAIN` fits one line in type pickers (e.g. Supabase Studio).
fn capability_phrase(domain: &Domain) -> String {
    let ops = Term::operators_for_terms(domain.terms);
    let mut caps = Vec::new();
    if ops.contains(&"=") {
        caps.push("equality");
    }
    if ops.contains(&"<") {
        caps.push("ordering");
    }
    if ops.contains(&"@@") {
        caps.push("matching");
    }
    if caps.is_empty() {
        "storage only".to_string()
    } else {
        caps.join(", ")
    }
}

/// Terse one-line `COMMENT ON DOMAIN` for a stored/searchable encrypted domain,
/// e.g. `EQL encrypted numeric (equality, ordering)`.
fn scalar_domain_comment(family_name: &str, domain: &Domain) -> String {
    sql_str(&format!(
        "EQL encrypted {family_name} ({})",
        capability_phrase(domain)
    ))
}

/// Terse `COMMENT ON DOMAIN` for a `_query` operand twin (index-terms-only).
fn query_domain_comment(family_name: &str, domain: &Domain) -> String {
    sql_str(&format!(
        "EQL {family_name} query operand ({})",
        capability_phrase(domain)
    ))
}

#[derive(serde::Serialize)]
pub struct TypesContext {
    pub family_name: String,
    pub domains: Vec<DomainBlock>,
}

/// Build the per-domain block data (port of `render_domain_block`'s value logic,
/// minus comment prose and the CHECK skeleton — those are template-resident).
pub fn domain_block(family_name: &str, domain: &Domain) -> DomainBlock {
    // Public-schema domains carry the eql_v3_ version prefix;
    // the catalog name stays bare.
    let name = public_typname(&domain.full_name(family_name));

    let mut keys: Vec<String> = ENVELOPE_KEYS.iter().map(|k| sql_str(k)).collect();
    for k in Term::term_json_keys(domain.terms) {
        keys.push(sql_str(k));
    }

    DomainBlock {
        // typname is sql_str-escaped defensively: the escaping boundary stays
        // Rust-side even though real catalog names carry no quotes.
        typname: sql_str(&name),
        name,
        keys,
        // Derived from the terms the same way `keys` is — the rule lives on
        // `Term::nonempty_array_key`, not here.
        nonempty_array_keys: Term::nonempty_array_keys(domain.terms)
            .into_iter()
            .map(sql_str)
            .collect(),
        // Storage domains forbid nothing; the query twin forbids `c`.
        forbidden_keys: vec![],
        comment: scalar_domain_comment(family_name, domain),
    }
}

/// The query-operand twin block for a term-bearing domain: `public.query_<name>`,
/// keys = envelope-minus-`c` (`v`/`i`) + the domain's terms, with `c` FORBIDDEN
/// (a query operand carries no ciphertext). Same non-empty-array term
/// rule as the storage block.
pub fn query_domain_block(family_name: &str, domain: &Domain) -> DomainBlock {
    let name = domain.query_name(family_name);

    // Envelope minus the ciphertext `c`, then the domain's terms.
    let mut keys: Vec<String> = ENVELOPE_KEYS
        .iter()
        .filter(|&&k| k != "c")
        .map(|k| sql_str(k))
        .collect();
    for k in Term::term_json_keys(domain.terms) {
        keys.push(sql_str(k));
    }

    DomainBlock {
        typname: sql_str(&name),
        name,
        keys,
        nonempty_array_keys: Term::nonempty_array_keys(domain.terms)
            .into_iter()
            .map(sql_str)
            .collect(),
        forbidden_keys: vec![sql_str("c")],
        comment: query_domain_comment(family_name, domain),
    }
}

/// One SQL parameter (name + SQL type), shared by wrapper and
/// unsupported-operator signatures and their `@param` docs tags.
#[derive(serde::Serialize)]
pub struct SqlParam {
    pub name: &'static str, // "a", "b", or "selector"
    pub ty: String,
}

/// One generated function entry. The serde tag drives the template's three-way
/// switch; the unsupported-operator arm is never merged with the others (footgun
/// separation — its body must always raise).
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
pub enum FnEntry {
    Extractor {
        ret: String,       // e.g. eql_v3_internal.hmac_256 (selection STAYS in Rust)
        extractor: String, // e.g. eq_term
        ctor: String,      // e.g. hmac_256 (called as {{ internal_schema }}.{{ ctor }})
    },
    Wrapper {
        op: String,            // SQL operator used in the body, e.g. =
        function_name: String, // e.g. eq
        args: [SqlParam; 2],
        call_a: String, // e.g. eql_v3.eq_term(a)   (embeds extract_arg cast logic)
        call_b: String, // e.g. eql_v3.eq_term(b::public.eql_v3_integer_eq)
        // True only for the `@@` bloom-match wrapper: appends the empty-needle
        // guard to the body so an empty needle bloom does not match every row.
        // See `Operator::needs_empty_bloom_guard`.
        empty_bloom_guard: bool,
    },
    Unsupported {
        operator_lit: String,  // sql_str(op), escaped content for the RAISE literal
        function_name: String, // e.g. lt / "->" / "#>"
        args: [SqlParam; 2],
        returns: String, // boolean / text / jsonb / domain (selection STAYS in Rust)
    },
}

#[derive(serde::Serialize)]
pub struct FunctionsContext {
    pub requires: Vec<String>, // dependency paths only; template emits "-- REQUIRE:"
    pub family_name: String,
    pub name: String,       // full domain name (family-name + "_" + domain-name)
    pub dom: String,        // schema-qualified domain, e.g. public.eql_v3_integer_eq
    pub domain_lit: String, // sql_str(dom), defensively escaped for the RAISE literal
    pub entries: Vec<FnEntry>,
}

/// Build the inlinable index-extractor entry for a domain term.
///
/// The `RETURNS` type name equals the constructor name (`hmac_256`,
/// `ore_block_256`); qualify it with `INTERNAL_SCHEMA` — the same schema as
/// the body's constructor call — so the declared return type and the call
/// stay in lockstep. `Term::returns()` is intentionally not used.
pub fn extractor_entry(term: Term) -> FnEntry {
    FnEntry::Extractor {
        ret: format!("{INTERNAL_SCHEMA}.{}", term.ctor()),
        extractor: term.extractor().to_string(),
        ctor: term.ctor().to_string(),
    }
}

/// Build an inlinable comparison-wrapper entry for a supported operator.
/// `dom` is the schema-qualified domain name; `op` is the already-resolved
/// operator (the caller iterates `OPERATORS`, so no symbol re-lookup is needed).
pub fn wrapper_entry(
    dom: &str,
    op: &Operator,
    arg_a: &str,
    arg_b: &str,
    extractor: &str,
) -> FnEntry {
    FnEntry::Wrapper {
        // Body operator: `symbol` for all but `@@`, whose body uses bloom `@>`.
        op: op.body_operator().to_string(),
        // Supported path → the public wrapper name. Differs from `function_name`
        // (the blocker name) only for `@@`, whose wrapper is `eql_v3.matches`.
        function_name: op.wrapper_function_name().to_string(),
        args: [
            SqlParam {
                name: "a",
                ty: arg_a.to_string(),
            },
            SqlParam {
                name: "b",
                ty: arg_b.to_string(),
            },
        ],
        call_a: extract_arg(arg_a, extractor, dom, "a"),
        call_b: extract_arg(arg_b, extractor, dom, "b"),
        empty_bloom_guard: op.needs_empty_bloom_guard(),
    }
}

/// Build an unsupported-operator entry. Every such entry shares one uniform
/// `RAISE EXCEPTION` body; only signature facts vary. `op` is the
/// already-resolved operator (no symbol re-lookup needed).
pub fn unsupported_entry(op: &Operator, args: [SqlParam; 2], returns: &str) -> FnEntry {
    FnEntry::Unsupported {
        // operator_lit is sql_str-escaped defensively for the single-quoted RAISE literal.
        operator_lit: sql_str(op.symbol.as_str()),
        function_name: op.function_name.to_string(),
        args,
        returns: returns.to_string(),
    }
}

/// One CREATE OPERATOR declaration, with the optional metadata line precomputed.
#[derive(serde::Serialize)]
pub struct OpEntry {
    pub symbol: String,
    pub function_name: String, // unqualified; function_schema qualifies it in the template
    // Schema of the backing function: SCHEMA (public `eql_v3`) for supported
    // operators — their comparison WRAPPER is public so the operator has a
    // callable function equivalent on platforms without operator support
    // (Supabase/PostgREST). INTERNAL_SCHEMA for blocked operators, whose backing
    // function is a blocker (anti-functionality, never a caller entrypoint).
    pub function_schema: String,
    pub leftarg: String,
    pub rightarg: String,
    pub metadata: Option<String>, // e.g. "COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel"
}

#[derive(serde::Serialize)]
pub struct OperatorsContext {
    pub requires: Vec<String>,
    pub family_name: String,
    pub name: String,
    pub dom: String,
    pub operators: Vec<OpEntry>,
}

/// Build one CREATE OPERATOR entry. Planner metadata is emitted only when the
/// current domain supports the operator and the operator carries metadata (the
/// `@>`/`<@` empty-metadata case collapses to `None`).
pub fn operator_entry(op: &Operator, leftarg: &str, rightarg: &str, supported: bool) -> OpEntry {
    let metadata = if supported {
        op.metadata.render()
    } else {
        None
    };
    // A supported operator is backed by a public comparison wrapper (SCHEMA); a
    // blocked one by an internal blocker (INTERNAL_SCHEMA). `supported` tracks
    // wrapper emission exactly: `is_supported(op) ⟹ extractor_for_operator is
    // Some`, so `render_functions_file` always emits a wrapper for a supported
    // operator and a blocker otherwise.
    let function_schema = if supported { SCHEMA } else { INTERNAL_SCHEMA };
    // Supported → the public wrapper name (`eql_v3.matches` for `@@`); blocked →
    // the blocker name (`eql_v3_internal."@@"`). They differ only for `@@`.
    let function_name = if supported {
        op.wrapper_function_name()
    } else {
        op.function_name
    };
    OpEntry {
        symbol: op.symbol.as_str().to_string(),
        function_name: function_name.to_string(),
        function_schema: function_schema.to_string(),
        leftarg: leftarg.to_string(),
        rightarg: rightarg.to_string(),
        metadata,
    }
}

#[derive(serde::Serialize)]
pub struct AggregatesContext {
    pub requires: Vec<String>, // dependency paths only; template emits "-- REQUIRE:"
    pub family_name: String,
    pub name: String,
    pub dom: String,                        // schema-qualified domain, hoisted
    pub aggregates: &'static [AggregateOp], // == AGGREGATE_OPS
}

/// Context for `ore_fallback.sql` — the cross-family capability-detection file
/// that poisons every ORE-carrying domain when the ORE operator
/// class could not be installed (non-superuser installer, e.g. cloud Supabase).
#[derive(serde::Serialize)]
pub struct OreFallbackContext {
    pub requires: Vec<String>, // dependency paths only; template emits "-- REQUIRE:"
    pub entries: Vec<OreFallbackEntry>,
}

/// One poisoned domain in `ore_fallback.sql`: the schema-qualified domain name
/// (`name` for the identifier position, `name_literal` sql_str-escaped for the
/// string-literal position in the poison CHECK) and the human-readable
/// alternatives its poison error steers callers to (the same family's non-ORE
/// term-bearing siblings, e.g.
/// `public.eql_v3_integer_eq (equality) or public.eql_v3_integer_ord_ope (ordering)`).
#[derive(serde::Serialize)]
pub struct OreFallbackEntry {
    pub name: String,
    pub name_literal: String,
    pub alternatives: String,
}

/// The bare pg_type typname of a public-schema encrypted domain: the catalog
/// name carrying the [`eql_domains::PUBLIC_TYPNAME_PREFIX`] version prefix,
/// e.g. `eql_v3_integer_eq`. The prefix keeps EQL domains from
/// shadowing PostgreSQL built-in type names (`integer`, `text`, `json`, …)
/// and gives each EQL version a distinct column-type namespace so multiple
/// versions can coexist in one database. Catalog names stay bare — the prefix
/// is applied only at SQL-name construction (file names, REQUIRE paths,
/// struct idents, and test names all keep the bare name).
pub fn public_typname(name: &str) -> String {
    format!("{}{name}", eql_domains::PUBLIC_TYPNAME_PREFIX)
}

/// The schema-qualified SQL domain type name, e.g. `public.eql_v3_integer_eq`.
/// User-column encrypted domains intentionally live in `public` so dropping
/// EQL-owned schemas cannot drop application columns.
pub fn domain_name(name: &str) -> String {
    format!("public.{}", public_typname(name))
}

/// The schema-qualified name of a QUERY-OPERAND domain, e.g.
/// `eql_v3.query_integer_eq`. Query twins live in the public-API `SCHEMA`
/// (not `public`) — they are never valid column types, so the
/// application-columns-survive-schema-drop rationale behind `domain_name`
/// does not apply, and keeping them out of `public` keeps the column-type
/// namespace to actual column types.
pub fn query_domain_name(name: &str) -> String {
    format!("{SCHEMA}.{name}")
}

/// The extractor-call SQL for one operand, casting jsonb to the domain first.
/// Port of `_extract_arg`. `dom` is the schema-qualified domain name.
pub fn extract_arg(arg_type: &str, extractor: &str, dom: &str, arg: &str) -> String {
    if arg_type == "jsonb" {
        format!("{SCHEMA}.{extractor}({arg}::{dom})")
    } else {
        format!("{SCHEMA}.{extractor}({arg})")
    }
}

/// One aggregate operator definition (min or max). Only SQL-required facts: the
/// state-function name is the mechanical suffix `{{ a.name }}_sfunc` in the
/// template, and English comment phrases are template-resident.
#[derive(serde::Serialize)]
pub struct AggregateOp {
    pub name: &'static str,       // min / max
    pub comparator: &'static str, // < / >
}

/// The two aggregate ops in (min, max) order. Port of `AGGREGATE_OPS`.
pub const AGGREGATE_OPS: &[AggregateOp] = &[
    AggregateOp {
        name: "min",
        comparator: "<",
    },
    AggregateOp {
        name: "max",
        comparator: ">",
    },
];

/// True if any of the domain's terms provides ordering (`<` `<=` `>` `>=`),
/// gating `min`/`max` aggregate emission. Asks a per-term *capability* (not the
/// whole-domain first-term `Role`), so a `[Hm, Ore]` domain — first term `Hm`,
/// `Role::Eq` — is still correctly ord-capable and emits aggregates.
pub fn is_ord_capable(terms: &[Term]) -> bool {
    terms.iter().any(|t| t.provides_ordering())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_name_qualifies_user_domains_with_public_schema() {
        assert_eq!(domain_name("integer_eq"), "public.eql_v3_integer_eq");
    }

    #[test]
    fn public_typname_carries_version_prefix() {
        assert_eq!(public_typname("integer"), "eql_v3_integer");
        assert_eq!(public_typname("text_match"), "eql_v3_text_match");
    }

    #[test]
    fn is_ord_capable_is_true_when_any_term_provides_ordering() {
        assert!(is_ord_capable(&[Term::Ore]));
        assert!(is_ord_capable(&[Term::Hm, Term::Ore]));
        assert!(is_ord_capable(&[Term::Hm, Term::Ore, Term::Bloom]));
        assert!(!is_ord_capable(&[Term::Hm]));
        assert!(!is_ord_capable(&[Term::Bloom]));
        assert!(!is_ord_capable(&[]));
    }

    #[test]
    fn is_ord_capable_unions_across_terms() {
        // An ord term anywhere in the list makes the domain ord-capable,
        // regardless of position — consistent with operators_for_terms' union,
        // not the first-term role. (No catalog domain is multi-term today; this
        // pins the order-independent semantics for a future mixed-term domain.)
        assert!(is_ord_capable(&[Term::Hm, Term::Ore]));
        assert!(is_ord_capable(&[Term::Ore, Term::Hm]));
        assert!(!is_ord_capable(&[Term::Hm, Term::Bloom]));
    }

    #[test]
    fn environment_has_whole_file_and_partial_templates() {
        let env = environment();
        for name in [
            // One whole-file template per generated SQL file.
            "types.sql",
            "functions.sql",
            "operators.sql",
            "aggregates.sql",
            // Per-kind partials included by functions.sql.
            "functions/extractor.sql.j2",
            "functions/wrapper.sql.j2",
            "functions/unsupported.sql.j2",
        ] {
            assert!(env.get_template(name).is_ok(), "missing template {name}");
        }
    }

    #[test]
    fn operator_entry_emits_metadata_only_when_supported() {
        use crate::operator_surface::operator;

        // (symbol, domain, supported) -> expected `CREATE OPERATOR` metadata
        // clause. Adding a term that carries operator metadata is one new row
        // here, not another hand-rolled assertion block.
        let cases: &[(&str, &str, bool, Option<&str>)] = &[
            // Supported comparison operator carries its planner metadata.
            (
                "=",
                "public.eql_v3_integer_eq",
                true,
                Some("COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel"),
            ),
            // The same operator, unsupported on this domain → no metadata line.
            ("=", "public.eql_v3_integer", false, None),
            // Supported but metadata-less operator (`->`) → still no metadata.
            ("->", "public.eql_v3_integer_eq", true, None),
            // `@@` (bloom fuzzy match) carries containment-style selectivity when
            // supported (the Bloom `text_match` path) — no commutator/negator, so
            // just the RESTRICT/JOIN estimators.
            (
                "@@",
                "public.eql_v3_text_match",
                true,
                Some("RESTRICT = contsel, JOIN = contjoinsel"),
            ),
            // `@>` carries containment metadata when explicitly supported (retained
            // for the hand-written JSON containment surface; the generated scalar
            // catalog no longer marks `@>` supported on any domain).
            (
                "@>",
                "public.eql_v3_text_match",
                true,
                Some("COMMUTATOR = <@, RESTRICT = contsel, JOIN = contjoinsel"),
            ),
            // ... but suppressed when `@>` is a blocker (its actual catalog state
            // on every domain now), which is why the integer reference is unchanged.
            ("@>", "public.eql_v3_integer_eq", false, None),
        ];

        for (symbol, dom, supported, expected) in cases {
            let entry = operator_entry(&operator(symbol), dom, dom, *supported);
            assert_eq!(entry.symbol, *symbol);
            assert_eq!(
                entry.metadata.as_deref(),
                *expected,
                "operator {symbol} on {dom} (supported={supported})",
            );
        }
    }
}
