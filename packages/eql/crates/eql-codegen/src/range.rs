//! The EQL v4 range surface: one range query domain per (family, ordering
//! term), its two bound accessors, and `between(column, range)` for every
//! stored domain that carries the term (ADR-0009, decisions 7 and 8).
//!
//! A `Between` query is one term holding both bounds (Stack Encrypt's
//! `RangeQuery`), and in SQL it stays one operand:
//!
//! ```sql
//! WHERE eql_v4.between(age, $1::eql_v4.query_integer_range_ore)
//! ```
//!
//! Each bound is the single-bound domain's `ob` (ORE) or `op` (OPE) value, in
//! a `{v, i, lo, hi}` envelope ([`RANGE_BOUND_KEYS`]): a bound of an ORE range
//! is an `ob` array, a bound of an OPE range an `op` hex string. The engine
//! does not build that envelope yet; it will need to when the ordered EQL
//! types become producible.
//!
//! The range parameter must be cast to its exact range domain. `between` has
//! many overloads over jsonb-backed domains, and PostgreSQL resolves a
//! function's domain arguments as their base type, so an uncast `$1`, a
//! `jsonb` parameter, or a range of the wrong term or family matches several
//! overloads and fails with 42725 ("function ... is not unique") before the
//! query runs. The single-bound operators resolve an untyped `$1`;
//! `between` does not.
//!
//! EQL v3 has none of this. v3 is what cipherstash-client writes, and nothing
//! there produces a range. Both files carry the `-- ONLY EQL VERSION: 4` line
//! ([`ONLY_DIRECTIVE`]), so the build renders
//! them into the v4 bundle only, and the renderer refuses to render them as v3.

use eql_domains::{DomainFamily, Term, RANGE_BOUND_KEYS};

use crate::consts::{sql_str, INTERNAL_SCHEMA};
use crate::context::{domain_name, environment, query_domain_name};
use crate::render::{EqlVersion, ONLY_DIRECTIVE};

/// The version the range surface belongs to.
pub const RANGE_VERSION: EqlVersion = EqlVersion::V4;

/// The directive line every range file carries: `-- ONLY EQL VERSION: 4`.
pub fn only_directive() -> String {
    format!("{ONLY_DIRECTIVE} {}", RANGE_VERSION.number())
}

/// The file holding a family's range domains: `query_integer_range_types.sql`.
pub fn range_types_file(family_name: &str) -> String {
    format!("query_{family_name}_range_types.sql")
}

/// The file holding a family's bound accessors and `between` overloads.
pub fn range_functions_file(family_name: &str) -> String {
    format!("query_{family_name}_range_functions.sql")
}

/// How a term reads in prose: `block ORE`, `CLLW OPE`. The SQL comments
/// and the binding structs' docs both read it here.
pub fn term_label(term: Term) -> &'static str {
    match term {
        Term::Ore => "block ORE",
        Term::Ope => "CLLW OPE",
        Term::Hm | Term::Bloom => unreachable!("{term:?} has no range domain"),
    }
}

/// The CHECK clauses one bound of a `term` range must satisfy: the shape the
/// single-bound query domain's term key has in EQL v4, a JSON string that
/// starts with one of the term's prefixes ([`eql_domains::V4TermFormat`]).
fn bound_checks(term: Term, bound: &str) -> Vec<String> {
    let format = term
        .v4_format()
        .unwrap_or_else(|| unreachable!("{term:?} has no range domain"));
    let prefixes = format
        .prefixes
        .iter()
        .map(|p| format!("'{}'", sql_str(p)))
        .collect::<Vec<_>>()
        .join(", ");
    let bound = sql_str(bound);
    vec![
        format!("jsonb_typeof(VALUE -> '{bound}') = 'string'"),
        format!(
            "left(VALUE ->> '{bound}', {}) IN ({prefixes})",
            format.prefixes[0].len()
        ),
    ]
}

/// The keys a range value must carry, in order: the envelope's `v` and `i`,
/// then the bounds ([`RANGE_BOUND_KEYS`]). What the domain CHECK requires
/// and what the binding structs' docs list.
pub fn range_required_keys() -> impl Iterator<Item = &'static str> {
    ["v", "i"].into_iter().chain(RANGE_BOUND_KEYS)
}

#[derive(serde::Serialize)]
struct RangeDomainBlock {
    name: String,
    typname: String,
    term_label: &'static str,
    keys: Vec<String>,
    bound_checks: Vec<String>,
    comment: String,
}

/// An ORE range domain the file disables when the install has no ORE
/// operator class, as `ore_fallback.sql` disables the single-bound ORE
/// domains: `name` for the identifier position, `name_literal` sql_str-escaped
/// for the poison error's message, `alternatives` for its hint.
#[derive(serde::Serialize)]
struct OreRangeFallback {
    name: String,
    name_literal: String,
    alternatives: String,
}

#[derive(serde::Serialize)]
struct RangeTypesContext {
    only_directive: String,
    family_name: String,
    requires: Vec<String>,
    domains: Vec<RangeDomainBlock>,
    ore_ranges: Vec<OreRangeFallback>,
}

/// The file whose poison function an ORE range's fallback calls.
const ORE_FALLBACK: &str = "src/v3/scalars/ore_fallback.sql";

/// The poison hint for an ORE range: the family's OPE range, which needs no
/// operator class. Every family with an ORE range has one today; a future
/// family without must still render a sentence.
fn ore_range_alternatives(spec: &DomainFamily) -> String {
    if spec.range_terms().contains(&Term::Ope) {
        format!(
            "{} (range)",
            query_domain_name(&spec.range_query_name(Term::Ope))
        )
    } else {
        "a non-ORE encrypted domain".to_string()
    }
}

/// Body of `query_<T>_range_types.sql`, or `None` for a family with no
/// ordering term.
///
/// An ORE range domain is disabled on an install without the ORE operator
/// class, as the single-bound ORE domains are. `ore_fallback.sql` cannot do
/// it, since it is shared with EQL v3 and the range domains are v4 only, so
/// this file adds the same NOT VALID poison CHECK to its own ORE range,
/// calling the function `ore_fallback.sql` creates under the same condition.
pub fn render_range_types_file(spec: &DomainFamily) -> Option<String> {
    let terms = spec.range_terms();
    if terms.is_empty() {
        return None;
    }
    let domains = terms
        .iter()
        .map(|&term| {
            let name = spec.range_query_name(term);
            RangeDomainBlock {
                typname: sql_str(&name),
                name,
                term_label: term_label(term),
                keys: range_required_keys().map(sql_str).collect(),
                bound_checks: RANGE_BOUND_KEYS
                    .iter()
                    .flat_map(|b| bound_checks(term, b))
                    .collect(),
                comment: sql_str(&format!(
                    "EQL {} range query operand ({})",
                    spec.name,
                    term_label(term)
                )),
            }
        })
        .collect();
    let ore_ranges: Vec<OreRangeFallback> = terms
        .iter()
        .filter(|&&t| t == Term::Ore)
        .map(|&t| {
            let name = query_domain_name(&spec.range_query_name(t));
            OreRangeFallback {
                name_literal: sql_str(&name),
                name,
                alternatives: sql_str(&ore_range_alternatives(spec)),
            }
        })
        .collect();
    let mut requires = vec!["src/v3/schema.sql".to_string()];
    if !ore_ranges.is_empty() {
        requires.push(ORE_FALLBACK.to_string());
    }
    let ctx = RangeTypesContext {
        only_directive: only_directive(),
        family_name: spec.name.to_string(),
        requires,
        domains,
        ore_ranges,
    };
    Some(
        environment()
            .get_template("range_types.sql")
            .unwrap()
            .render(&ctx)
            .expect("render range_types.sql"),
    )
}

#[derive(serde::Serialize)]
struct Accessor {
    side: &'static str,
    function_name: &'static str,
    range: String,
    term_label: &'static str,
    returns: String,
    body: String,
}

#[derive(serde::Serialize)]
struct Between {
    column: String,
    range: String,
    extractor: &'static str,
    /// An ORE range, whose index needs the opclass a non-superuser
    /// install skips: the generated docs say so.
    ore: bool,
    /// For an ORE range, the family's OPE column domains and OPE range,
    /// which the generated docs point to instead. Empty otherwise.
    ope_columns: String,
    ope_range: String,
}

#[derive(serde::Serialize)]
struct RangeFunctionsContext {
    only_directive: String,
    family_name: String,
    requires: Vec<String>,
    accessors: Vec<Accessor>,
    betweens: Vec<Between>,
}

/// Body of `query_<T>_range_functions.sql`, or `None` for a family with no
/// ordering term: `lo` and `hi` for each range domain (in the internal
/// schema: only `between` calls them), then
/// `between(column, range)` for each stored domain carrying the range's term.
///
/// An accessor reads its bound with the term's own constructor
/// (`ore_block_256` / `ope_cllw` over `{"ob": …}` / `{"op": …}`), the one
/// path a single-bound term is read by. `between` compares the column's
/// extractor, the expression a functional index is built on, against both.
pub fn render_range_functions_file(spec: &DomainFamily) -> Option<String> {
    let terms = spec.range_terms();
    if terms.is_empty() {
        return None;
    }
    let family_name = spec.name;
    let mut requires = vec![
        "src/v3/schema.sql".to_string(),
        format!(
            "src/v3/scalars/{family_name}/{}",
            range_types_file(family_name)
        ),
    ];
    let mut accessors = Vec::new();
    let mut betweens = Vec::new();
    let ope_columns = spec
        .range_columns(Term::Ope)
        .iter()
        .map(|d| format!("`{}`", domain_name(&d.full_name(family_name))))
        .collect::<Vec<_>>()
        .join(", ");
    let ope_range = if terms.contains(&Term::Ope) {
        format!("`{}`", query_domain_name(&spec.range_query_name(Term::Ope)))
    } else {
        String::new()
    };
    for &term in &terms {
        let range = spec.range_query_name(term);
        let returns = format!("{INTERNAL_SCHEMA}.{}", crate::consts::sql_ctor(term));
        for (side, function_name, bound) in [
            ("low", "lo", RANGE_BOUND_KEYS[0]),
            ("high", "hi", RANGE_BOUND_KEYS[1]),
        ] {
            accessors.push(Accessor {
                side,
                function_name,
                range: range.clone(),
                term_label: term_label(term),
                returns: returns.clone(),
                body: format!(
                    "{INTERNAL_SCHEMA}.{}(jsonb_build_object('{}', r::jsonb -> '{}'))",
                    crate::consts::sql_ctor(term),
                    sql_str(term.json_key()),
                    sql_str(bound)
                ),
            });
        }
        for domain in spec.range_columns(term) {
            let full = domain.full_name(family_name);
            let functions = format!("src/v3/scalars/{family_name}/{full}_functions.sql");
            if !requires.contains(&functions) {
                requires.push(functions);
            }
            betweens.push(Between {
                column: domain_name(&full),
                range: range.clone(),
                extractor: term.extractor(),
                ore: term == Term::Ore,
                ope_columns: if term == Term::Ore {
                    ope_columns.clone()
                } else {
                    String::new()
                },
                ope_range: if term == Term::Ore {
                    ope_range.clone()
                } else {
                    String::new()
                },
            });
        }
    }
    for extra in Term::term_requires(&terms) {
        if !requires.iter().any(|r| r == extra) {
            requires.push(extra.to_string());
        }
    }
    let ctx = RangeFunctionsContext {
        only_directive: only_directive(),
        family_name: family_name.to_string(),
        requires,
        accessors,
        betweens,
    };
    Some(
        environment()
            .get_template("range_functions.sql")
            .unwrap()
            .render(&ctx)
            .expect("render range_functions.sql"),
    )
}

/// The schema-qualified range domain for `term` under `spec`, as a v4 SQL
/// name: `eql_v4.query_integer_range_ore`. What the bindings name.
pub fn range_sql_domain(spec: &DomainFamily, term: Term) -> String {
    format!("{}.{}", RANGE_VERSION.prefix(), spec.range_query_name(term))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{belongs_to, render_str};
    use eql_domains::{BOOLEAN, CATALOG, JSON, TEXT};

    fn integer() -> &'static DomainFamily {
        CATALOG.iter().find(|f| f.name == "integer").unwrap()
    }

    #[test]
    fn a_family_without_ordering_has_no_range_files() {
        for f in [&BOOLEAN, &JSON] {
            assert!(render_range_types_file(f).is_none(), "{}", f.name);
            assert!(render_range_functions_file(f).is_none(), "{}", f.name);
        }
    }

    #[test]
    fn range_files_belong_to_eql_v4_only() {
        for f in CATALOG.iter().filter(|f| !f.range_terms().is_empty()) {
            for body in [
                render_range_types_file(f).unwrap(),
                render_range_functions_file(f).unwrap(),
            ] {
                assert_eq!(body.lines().nth(1), Some("-- ONLY EQL VERSION: 4"));
                assert_eq!(belongs_to(&body, EqlVersion::V4), Ok(true));
                assert_eq!(belongs_to(&body, EqlVersion::V3), Ok(false));
                assert!(render_str(&body, EqlVersion::V3).is_err());
                render_str(&body, EqlVersion::V4).unwrap();
            }
        }
    }

    #[test]
    fn the_range_domains_check_the_bound_shape_of_their_term() {
        let v4 = render_str(&render_range_types_file(integer()).unwrap(), EqlVersion::V4).unwrap();
        assert!(v4.contains("CREATE DOMAIN eql_v4.query_integer_range_ore AS jsonb"));
        assert!(v4.contains("CREATE DOMAIN eql_v4.query_integer_range_ope AS jsonb"));
        let ore = v4
            .split("CREATE DOMAIN eql_v4.query_integer_range_ore")
            .nth(1)
            .unwrap()
            .split("END IF;")
            .next()
            .unwrap();
        for clause in [
            "VALUE ? 'v'",
            "VALUE ? 'i'",
            "VALUE ? 'lo'",
            "VALUE ? 'hi'",
            "NOT (VALUE ? 'c')",
            "jsonb_typeof(VALUE -> 'lo') = 'string'",
            "left(VALUE ->> 'lo', 4) IN ('0202', '0203')",
            "jsonb_typeof(VALUE -> 'hi') = 'string'",
            "left(VALUE ->> 'hi', 4) IN ('0202', '0203')",
            "COALESCE(VALUE->>'v' = '4', VALUE IS NULL)",
        ] {
            assert!(ore.contains(clause), "ORE range lacks {clause}:\n{ore}");
        }
        let ope = v4
            .split("CREATE DOMAIN eql_v4.query_integer_range_ope")
            .nth(1)
            .unwrap()
            .split("END IF;")
            .next()
            .unwrap();
        assert!(ope.contains("jsonb_typeof(VALUE -> 'lo') = 'string'"));
        assert!(ope.contains("left(VALUE ->> 'lo', 2) IN ('00', '01')"));
        assert!(ope.contains("jsonb_typeof(VALUE -> 'hi') = 'string'"));
        assert!(ope.contains("left(VALUE ->> 'hi', 2) IN ('00', '01')"));
        assert!(!ope.contains("jsonb_array_length"), "{ope}");
        assert!(!ore.contains("jsonb_array_length"), "{ore}");
        assert!(v4.contains(
            "COMMENT ON DOMAIN eql_v4.query_integer_range_ore IS 'EQL integer range query operand (block ORE)'"
        ));
        assert!(v4.contains(
            "COMMENT ON DOMAIN eql_v4.query_integer_range_ope IS 'EQL integer range query operand (CLLW OPE)'"
        ));
    }

    #[test]
    fn between_is_inlinable_and_compares_the_column_extractor_to_both_bounds() {
        let v4 = render_str(
            &render_range_functions_file(integer()).unwrap(),
            EqlVersion::V4,
        )
        .unwrap();
        assert!(v4.contains(
            "CREATE FUNCTION eql_v4.between(a public.eql_v4_integer_ord_ore, r eql_v4.query_integer_range_ore)\n\
             RETURNS boolean\n\
             LANGUAGE sql IMMUTABLE PARALLEL SAFE\n\
             AS $$ SELECT eql_v4.ord_term_ore(a) >= eql_v4_internal.lo(r) AND eql_v4.ord_term_ore(a) <= eql_v4_internal.hi(r) $$;"
        ), "{v4}");
        // OPE serves both OPE-backed column domains.
        for column in ["public.eql_v4_integer_ord", "public.eql_v4_integer_ord_ope"] {
            assert!(v4.contains(&format!(
                "CREATE FUNCTION eql_v4.between(a {column}, r eql_v4.query_integer_range_ope)\n\
                 RETURNS boolean\n\
                 LANGUAGE sql IMMUTABLE PARALLEL SAFE\n\
                 AS $$ SELECT eql_v4.ord_term(a) >= eql_v4_internal.lo(r) AND eql_v4.ord_term(a) <= eql_v4_internal.hi(r) $$;"
            )), "{column}");
        }
        assert_eq!(v4.matches("CREATE FUNCTION eql_v4.between(").count(), 3);
        // Inlining needs no STRICT and no SET clause on `between`.
        for between in v4.split("CREATE FUNCTION eql_v4.between(").skip(1) {
            let header = between.split("AS $$").next().unwrap();
            assert!(!header.contains("STRICT"), "{header}");
            assert!(!header.contains("SET "), "{header}");
        }
    }

    #[test]
    fn each_bound_is_read_by_its_terms_own_constructor() {
        let v4 = render_str(
            &render_range_functions_file(integer()).unwrap(),
            EqlVersion::V4,
        )
        .unwrap();
        for (side, bound) in [("lo", "lo"), ("hi", "hi")] {
            assert!(v4.contains(&format!(
                "CREATE FUNCTION eql_v4_internal.{side}(r eql_v4.query_integer_range_ore)\n\
                 RETURNS eql_v4_internal.ore_block_v2\n\
                 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE\n\
                 AS $$ SELECT eql_v4_internal.ore_block_v2(jsonb_build_object('ob', r::jsonb -> '{bound}')) $$;"
            )), "{side} ORE");
            assert!(v4.contains(&format!(
                "CREATE FUNCTION eql_v4_internal.{side}(r eql_v4.query_integer_range_ope)\n\
                 RETURNS eql_v4_internal.ope_cllw\n\
                 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE\n\
                 AS $$ SELECT eql_v4_internal.ope_cllw(jsonb_build_object('op', r::jsonb -> '{bound}')) $$;"
            )), "{side} OPE");
        }
    }

    #[test]
    fn the_functions_file_requires_what_it_calls() {
        let body = render_range_functions_file(&TEXT).unwrap();
        let requires: Vec<&str> = body
            .lines()
            .filter_map(|l| l.strip_prefix("-- REQUIRE: "))
            .collect();
        assert_eq!(
            requires,
            [
                "src/v3/schema.sql",
                "src/v3/scalars/text/query_text_range_types.sql",
                "src/v3/scalars/text/text_ord_ore_functions.sql",
                "src/v3/scalars/text/text_search_ore_functions.sql",
                "src/v3/scalars/text/text_ord_functions.sql",
                "src/v3/scalars/text/text_ord_ope_functions.sql",
                "src/v3/scalars/text/text_search_functions.sql",
                "src/v3/sem/ore_block_256/functions.sql",
                "src/v3/sem/ore_block_256/operators.sql",
                "src/v3/sem/ope_cllw/functions.sql",
            ]
        );
        // Five text column domains carry an ordering term: five overloads.
        assert_eq!(
            body.matches("CREATE FUNCTION {{prefix}}.between(").count(),
            5
        );
        assert_eq!(
            body.matches("CREATE FUNCTION {{prefix}}_internal.lo(")
                .count(),
            2
        );
        assert_eq!(
            body.matches("CREATE FUNCTION {{prefix}}_internal.hi(")
                .count(),
            2
        );
    }

    /// Only the ORE `between` overloads say their index needs the
    /// `ore_block_256` btree opclass, which a non-superuser install skips;
    /// the OPE ones index everywhere.
    #[test]
    fn the_ore_overloads_name_the_opclass_they_need() {
        let body = render_range_functions_file(integer()).unwrap();
        for overload in body.split("--! @brief Whether ").skip(1) {
            let ore = overload.contains("_range_ore)");
            assert_eq!(
                overload.contains("default btree operator class"),
                ore,
                "{overload}"
            );
        }
    }

    /// The ORE note names the family's own OPE columns and OPE range, not a
    /// fixed list: only text has a `_search` domain.
    #[test]
    fn the_ore_note_names_the_familys_own_ope_columns() {
        let integer = render_range_functions_file(integer()).unwrap();
        assert!(
            integer.contains(
                "use an OPE column (`public.{{prefix}}_integer_ord`, \
                 `public.{{prefix}}_integer_ord_ope`)\n--!       and `{{prefix}}.query_integer_range_ope`"
            ),
            "{integer}"
        );
        assert!(!integer.contains("_search"), "{integer}");
        let text = render_range_functions_file(&TEXT).unwrap();
        assert!(text.contains("`public.{{prefix}}_text_search`"), "{text}");
    }

    /// An ORE range is disabled where the single-bound ORE domains are: the
    /// file requires `ore_fallback.sql`, whose poison function it calls, and
    /// adds the poison CHECK to the ORE range alone, behind the same opclass
    /// check, with the OPE range as the hint.
    #[test]
    fn the_ore_range_is_disabled_without_the_ore_opclass() {
        for f in CATALOG.iter().filter(|f| !f.range_terms().is_empty()) {
            let body = render_range_types_file(f).unwrap();
            let ore = f.range_terms().contains(&Term::Ore);
            assert_eq!(
                body.contains("-- REQUIRE: src/v3/scalars/ore_fallback.sql"),
                ore,
                "{}",
                f.name
            );
            let v4 = render_str(&body, EqlVersion::V4).unwrap();
            let alters: Vec<&str> = v4
                .lines()
                .filter(|l| l.contains("ADD CONSTRAINT eql_ore_unavailable"))
                .collect();
            if !ore {
                assert!(alters.is_empty(), "{}", f.name);
                continue;
            }
            let name = format!("eql_v4.query_{}_range_ore", f.name);
            assert_eq!(
                alters,
                [format!(
                    "  ALTER DOMAIN {name} ADD CONSTRAINT eql_ore_unavailable"
                )],
                "{}",
                f.name
            );
            assert!(
                v4.contains(&format!(
                    "CHECK (eql_v4_internal.ore_domain_unavailable(VALUE, '{name}', \
                     'eql_v4.query_{}_range_ope (range)')) NOT VALID;",
                    f.name
                )),
                "{v4}"
            );
            assert!(
                v4.contains("AND c.opcintype = 'eql_v4_internal.ore_block_v2'::pg_catalog.regtype")
            );
        }
    }

    #[test]
    fn every_function_is_documented() {
        for f in CATALOG.iter().filter(|f| !f.range_terms().is_empty()) {
            let body = render_range_functions_file(f).unwrap();
            let functions = body.matches("\nCREATE FUNCTION ").count();
            assert_eq!(
                body.matches("\n--! @brief ").count(),
                functions + 1,
                "{}",
                f.name
            );
            assert_eq!(
                body.matches("\n--! @return ").count(),
                functions,
                "{}",
                f.name
            );
        }
    }

    #[test]
    fn the_sql_domain_names_the_v4_schema() {
        assert_eq!(
            range_sql_domain(integer(), Term::Ope),
            "eql_v4.query_integer_range_ope"
        );
    }
}
